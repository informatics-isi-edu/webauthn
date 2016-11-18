#include <httpd.h>
#include <http_config.h>
#include <http_request.h>
#include <http_protocol.h>
#include <http_log.h>
#include <mod_auth.h>
#include <ap_hooks.h>
#include <apr.h>
#include <apr_strings.h>
#include <apr_uri.h>
#include <apr_tables.h>
#include <apr_pools.h>
#include <apr_thread_rwlock.h>
#include <apr_base64.h>
#include <ap_expr.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <util_cookies.h>
#include <apr_time.h>
#include <unistd.h>

#define WEBAUTHN_GROUP "webauthn-group"
#define WEBAUTHN_SESSION_BASE64 "WEBAUTHN_SESSION_BASE64"
#define USER_DISPLAY_NAME "USER_DISPLAY_NAME"
#define VARY_HEADERS = "WEBAUTHN_VARY_HEADERS"
/* These next two are defined by curl */
#define VERIFY_SSL_HOST_OFF 0
#define VERIFY_SSL_HOST_ON 2
#define MULTI_WAIT_USECS 100000

#define VERIFY_STRING "verify"
#define NOVERIFY_STRING "noverify"

#define WEBAUTHN_DEFAULT_CACHE_SECONDS -1
static void register_hooks(apr_pool_t *pool);
static int webauthn_check_user_id(request_rec * r);
static const char *webauthn_set_login_path(cmd_parms *cmd, void *cfg, const char *arg);
static const char *webauthn_set_session_path(cmd_parms *cmd, void *cfg, const char *arg);
static const char *webauthn_set_verify_ssl_host(cmd_parms *cmd, void *cfg, const char *arg);
static const char *webauthn_set_cookie_name(cmd_parms *cmd, void *cfg, const char *arg);
static int webauthn_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp);
static size_t webauthn_curl_write_callback(char *indata, size_t size, size_t nitems, void *buffer);
static void *create_local_conf(apr_pool_t *pool, char *context);
static CURLcode do_simple_perform(CURL *curl);
static authz_status webauthn_group_check_authorization(request_rec *r, const char *require_args, const void *parsed_require_args);
static const char *webauthn_set_max_cache_seconds(cmd_parms *cmd, void *cfg, const char *arg);
static const char *webauthn_parse_config(cmd_parms *cmd, const char *require_line, const void **parsed_require_line);
static const char *webauthn_add_group_alias(cmd_parms *cmd, void *cfg, const char *alias, const char *group, const char *verify);
static void *merge_local_conf(apr_pool_t *pool, void *parent_cfg, void *child_cfg);

typedef struct {
  apr_hash_t *hash;
  apr_pool_t *hash_pool_parent;
  apr_thread_rwlock_t *hash_lock;
} managed_hash;

static void *get_managed_hash_entry(managed_hash *mhash, const char *key);
static void add_managed_hash_entry(managed_hash *mhash, const char *key, void *data);
static void delete_managed_hash_entry(managed_hash *mhash, const char *key, apr_pool_t *data_pool);
static managed_hash *create_managed_hash(apr_pool_t *pool);
static const char *webauthn_set_if_unauthn(cmd_parms *cmd, void *cfg, const char *arg);

typedef struct {
  char *session_path;
  char *login_path;
  char *cookie_name;
  managed_hash *session_hash;
  managed_hash *alias_hash;
  int max_cache_seconds;
  int verify_ssl_host;
} webauthn_config;


static webauthn_config config;

typedef enum {
  ua_redirect,
  ua_fail,
  ua_unset
} unauthn_response;

const static unauthn_response DEFAULT_UNAUTHN_RESPONSE = ua_fail;

typedef struct {
  char *context;
  apr_pool_t *pool;
  managed_hash *alias_hash;
  unauthn_response if_unauthn;
} webauthn_local_config;

typedef struct {
  request_rec *r;
  apr_pool_t *pool;
  struct {
    char *data;
    int size;
  } segments[100];
  int current_data_index;
} webauthn_http_data;

static CURL *create_curl_handle(request_rec *r, const char *url, webauthn_http_data *data, char *errbuf);

static char *consolidate_segments(webauthn_http_data *data);

typedef struct {
  const char *id;
  const char *display_name;
} webauthn_group;

static webauthn_group *get_groups_from_json_array(json_object *jobj, request_rec *r);

typedef struct {
  const char *id;
  const char *display_name;
  const char *full_name;
  const char *email;
} webauthn_user;

static webauthn_user *make_temp_user_from_json(json_object *jobj, request_rec *r);

typedef struct {
  const char *sessionid;
  apr_time_t timeout;
  webauthn_user *user;
  webauthn_group *groups;
  apr_pool_t *pool;
  const char *base64_session_string;
} session_info;

typedef struct {
  const char *alias;
  const char *group;
  int verify;
} group_alias;


static group_alias *clone_group_alias(apr_pool_t *pool, const group_alias *old);
static session_info *get_cached_session_info(const char *sessionid);
static session_info *make_session_info(request_rec *r, apr_pool_t *parent_pool, const char *sessionid, char *json_string);
static session_info *webauthn_make_session_info_from_scratch(request_rec * r, webauthn_local_config *local_config);
static void cache_sessioninfo(session_info *sinfo, request_rec *r);
static int valid_unexpired_session(session_info *sinfo);
static void delete_cached_session_info(session_info *sinfo);
static void set_request_vals(request_rec *r, session_info *sinfo);
static session_info *find_or_create_session_info(request_rec *r, webauthn_local_config *local_config);

static void curl_add_put_nothing_opts(request_rec *r, CURL *curl, const char *sessionid);

typedef struct {
  CURLMcode mcode;
  CURLcode ccode;
} multi_codes;

static multi_codes *do_multi_perform(CURL *curl, request_rec *r);

static const command_rec webauthn_directives[] =
  {
    AP_INIT_TAKE1("WebauthnLoginPath", webauthn_set_login_path, NULL, RSRC_CONF, "Relative url for login"),
    AP_INIT_TAKE1("WebauthnCookieName", webauthn_set_cookie_name, NULL, RSRC_CONF, "Webauthn cookie name"),
    AP_INIT_TAKE1("WebauthnSessionPath", webauthn_set_session_path, NULL, RSRC_CONF, "Relative url for session query"),
    AP_INIT_TAKE1("WebauthnVerifySslHost", webauthn_set_verify_ssl_host, NULL, RSRC_CONF, "Flag to validate ssl hostname for login/session urls"),
    AP_INIT_TAKE1("WebauthnMaxCacheSeconds", webauthn_set_max_cache_seconds, NULL, RSRC_CONF, "Maximum number of seconds to cache session info before querying webauthn"),
    AP_INIT_TAKE23("WebauthnAddGroupAlias", webauthn_add_group_alias, NULL, (RSRC_CONF | OR_AUTHCFG), "Create an alias that can be used in 'Require webauthn-group' directives."),
    AP_INIT_TAKE1("WebauthnIfUnauthn", webauthn_set_if_unauthn, NULL, RSRC_CONF | OR_AUTHCFG, "Action to take (redirect, json, or fail) if the user isn't logged in"),
    { NULL }
  };

module AP_MODULE_DECLARE_DATA webauthn_module =
  {
    STANDARD20_MODULE_STUFF,
    create_local_conf,
    merge_local_conf,
    NULL,
    NULL,
    webauthn_directives,
    register_hooks   /* Our hook registering function */
  };

static const authz_provider authz_webauthn_group_provider =
  {
    &webauthn_group_check_authorization,
    &webauthn_parse_config
  };


static void register_hooks(apr_pool_t *pool)
{
  /* Create a hook in the request handler, so we get called when a request arrives */
  ap_hook_check_authn(webauthn_check_user_id, NULL, NULL, APR_HOOK_FIRST, AP_AUTH_INTERNAL_PER_URI);
  ap_hook_pre_config(webauthn_pre_config, NULL, NULL, APR_HOOK_FIRST);
  ap_register_auth_provider(pool, AUTHZ_PROVIDER_GROUP, WEBAUTHN_GROUP,
			    AUTHZ_PROVIDER_VERSION,
			    &authz_webauthn_group_provider,
			    AP_AUTH_INTERNAL_PER_CONF);


}


static session_info *find_or_create_session_info(request_rec *r, webauthn_local_config *local_config) {
  const char *sessionid = 0;
  session_info *sinfo = 0;
  ap_cookie_read(r, config.cookie_name, &sessionid, 0);
  if (sessionid != NULL) {
    sinfo = get_cached_session_info(sessionid);
  }

  if (! valid_unexpired_session(sinfo)) {
    if (sinfo) {
      char ts[APR_CTIME_LEN];
      apr_ctime(ts, sinfo->timeout);
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "cache entry for session %s expired at %s, deleting", sinfo->sessionid, ts);
      delete_cached_session_info(sinfo);
      sinfo = 0;
    } else {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "cache entry for session %s not found", sessionid);
    }
  }

  if (sinfo == NULL) {
    if ((sinfo = webauthn_make_session_info_from_scratch(r, local_config)) != NULL) {
      cache_sessioninfo(sinfo, r);
    }
  }
  return sinfo;
}

static int webauthn_check_user_id(request_rec *r)
{
  int retval = HTTP_UNAUTHORIZED;
  webauthn_local_config *local_config = (webauthn_local_config *) ap_get_module_config(r->per_dir_config, &webauthn_module);
  session_info *sinfo = find_or_create_session_info(r, local_config);
  
  if (sinfo) {
    set_request_vals(r, sinfo);
    retval = OK;
  }
  return(retval);
}

static void set_request_vals(request_rec *r, session_info *sinfo) {
  if (sinfo->user) {
    r->user = apr_pstrdup(r->pool, sinfo->user->id);
    if (r->subprocess_env == NULL) {
      r->subprocess_env = apr_table_make(r->pool, 1);
    }
    apr_table_set(r->subprocess_env, WEBAUTHN_SESSION_BASE64, apr_pstrdup(r->pool, sinfo->base64_session_string));
    if (sinfo->user->display_name) {
      apr_table_set(r->subprocess_env, USER_DISPLAY_NAME, apr_pstrdup(r->pool, sinfo->user->display_name));
    }
  }
}

static session_info *webauthn_make_session_info_from_scratch(request_rec * r, webauthn_local_config *local_config)
{
  int debug = 0;
  session_info *sinfo = 0;
  unauthn_response if_unauthn = (local_config->if_unauthn == ua_unset ? DEFAULT_UNAUTHN_RESPONSE : local_config->if_unauthn);

  const char *session_uri=apr_psprintf(r->pool, "https://%s%s", r->hostname, config.session_path);
  const char *login_uri=apr_psprintf(r->pool, "https://%s%s?%sreferrer=%s",
				     r->hostname, config.login_path,
				     (if_unauthn == ua_redirect ? "do_redirect=true&" : ""),
				     /*				     ap_escape_urlencoded(r->pool, r->unparsed_uri)); */
  				     ap_escape_uri(r->pool, r->unparsed_uri)); 
  const char *sessionid = 0;
  ap_cookie_read(r, config.cookie_name, &sessionid, 0);
  ap_set_content_type(r, "text/plain");
  apr_time_t now = apr_time_now();
  char time_string[APR_CTIME_LEN];
  apr_ctime(time_string, now);
  CURL *session_curl = 0;

  if (sessionid == NULL) {	/* no session cookie */
    goto end;
  }

  webauthn_http_data *data = (webauthn_http_data *)apr_pcalloc(r->pool, sizeof(webauthn_http_data));
  char *errbuf = apr_pcalloc(r->pool, CURL_ERROR_SIZE);
  session_curl = create_curl_handle(r, session_uri, data, errbuf);

  if(session_curl) {
    /* To extend the webauthn session lifetime, use PUT instead of GET */
    curl_add_put_nothing_opts(r, session_curl, sessionid);
    CURLcode ccode;
    if (debug) {
      ccode = do_simple_perform(session_curl);
    } else {
      multi_codes *curl_codes = do_multi_perform(session_curl, r);
      if (curl_codes->mcode != CURLM_OK) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		      "multi_perform (%s) failed: %s\n",
		      session_uri, curl_multi_strerror(curl_codes->mcode));
	goto end;
      }
      ccode = curl_codes->ccode;
    }
    if (ccode != CURLE_OK) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		      "easy_perform (%s) failed: %s\n",
		      session_uri, (*errbuf ? errbuf : curl_easy_strerror(ccode)));
	goto end;
    }

    long http_code;
    curl_easy_getinfo (session_curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != HTTP_OK) {
      goto end;
    }

    char *json_string = consolidate_segments(data);
    sinfo = make_session_info(r, config.session_hash->hash_pool_parent, sessionid, json_string);
  }
 end:
  if (session_curl) {
    curl_easy_cleanup(session_curl);
  }
  if (sinfo == NULL) {
    if (if_unauthn == ua_fail) {
      if (r->err_headers_out == NULL) {
	r->err_headers_out = apr_table_make(r->pool, 1);
      }
      apr_table_setn(r->err_headers_out, "WWW-Authenticate", apr_psprintf(r->pool, "Webauthn: preauth=%s", login_uri));
    } else {
      ap_internal_redirect(login_uri, r);
    }
  }
  return sinfo;
}

  static CURL *create_curl_handle(request_rec *r, const char *url, webauthn_http_data *data, char *errbuf)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    data->pool = r->pool;
    data->r = r;
    data->current_data_index = 0;
      
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, webauthn_curl_write_callback); 
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)data); 
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, (void *)errbuf); 
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, config.verify_ssl_host);
  }
  return(curl);
}

static void curl_add_put_nothing_opts(request_rec *r, CURL *curl, const char *sessionid)
{
  /* CURLOPT_UPLOAD appears to be broken, so do this instead */
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
  char *cookie_string = apr_psprintf(r->pool, "%s=%s", config.cookie_name, sessionid);
  curl_easy_setopt(curl, CURLOPT_COOKIE, cookie_string); 
}


static const char *clone_string(apr_pool_t *pool, const char *string) {
  return (string ? apr_pstrdup(pool, string) : NULL);
}

static webauthn_user *clone_user(apr_pool_t *pool, webauthn_user *user) {
  webauthn_user *new_user = apr_pcalloc(pool, sizeof(webauthn_user));
  new_user->id = clone_string(pool, user->id);
  new_user->display_name = clone_string(pool, user->display_name);
  new_user->full_name = clone_string(pool, user->full_name);
  new_user->email = clone_string(pool, user->email);
  return(new_user);
}

static apr_time_t make_session_timeout(int server_seconds) {
  int secs = server_seconds / 2;
  if ((config.max_cache_seconds != WEBAUTHN_DEFAULT_CACHE_SECONDS) && (secs > config.max_cache_seconds)) {
    secs = config.max_cache_seconds;
  }

  if (config.max_cache_seconds == 0) {
    secs = 0;
  } else {
    secs += apr_time_sec(apr_time_now());
  }
    return apr_time_from_sec(secs);
}
static session_info *make_session_info(request_rec *r, apr_pool_t *parent_pool, const char *sessionid, char *json_string)
{
  /*
   * If we're caching, the session info can't go into the request's pool (because that's subject to being
   * freed when the request is done) and shouldn't go into the config pool (because clearing a pool is
   * all-or-nothing; you can't say "clear the part of the pool associated with this deleted hash entry, but
   * leave the rest of the pool alone"). So we make a new pool for each hash entry.
   */

  apr_pool_t *pool = 0;
  apr_pool_create(&pool, parent_pool);
  session_info *sess = apr_pcalloc(pool, sizeof(session_info));
  sess->pool = pool;
  sess->sessionid = apr_pstrdup(pool, sessionid);
  sess->base64_session_string = ap_pbase64encode(pool, json_string);

  json_object *jobj = json_tokener_parse(json_string);
  webauthn_group *groups = 0;
  int session_seconds = 0;
  webauthn_user *temp_user = 0; /* values not allocated in session_info pool */
  json_object_object_foreach(jobj, key, val) {
    if ((strcmp(key, "attributes") == 0) && json_object_is_type(val, json_type_array)) {
      groups = get_groups_from_json_array(val, r);
    } else if (strcmp(key, "client") == 0) {
      temp_user = make_temp_user_from_json(val, r);
    } else if ((strcmp(key, "seconds_remaining") == 0) && json_object_is_type(val, json_type_int)) {
      session_seconds = json_object_get_int(val);
    }
  }

  if (temp_user) {
    sess->user = clone_user(pool, temp_user);
  }

  sess->timeout = make_session_timeout(session_seconds);
  int len = 0;
  if (groups) {
    while (groups[len].id) {
      len++;
    }
    sess->groups = apr_pcalloc(pool, (len+1) * sizeof(webauthn_group));
    for (int i=0; i<len; i++) {
      sess->groups[i].id = apr_pstrdup(pool, groups[i].id);
      if (groups[i].display_name) {
	sess->groups[i].display_name = apr_pstrdup(pool, groups[i].display_name);
      }
    }
  }
  return(sess);
}

static const char *webauthn_set_login_path(cmd_parms *cmd, void *cfg, const char *arg)
{
  config.login_path = apr_pstrdup(cmd->pool, arg);
  return NULL;
}

static const char *webauthn_set_cookie_name(cmd_parms *cmd, void *cfg, const char *arg)
{
  config.cookie_name = apr_pstrdup(cmd->pool, arg);
  return NULL;
}

static const char *webauthn_set_if_unauthn(cmd_parms *cmd, void *cfg, const char *arg)
{
  webauthn_local_config *lcfg = (webauthn_local_config *)cfg;
  if (strcasecmp(arg, "redirect") == 0) {
    lcfg->if_unauthn = ua_redirect;
  } else if (strcasecmp(arg, "fail") == 0) {
    lcfg->if_unauthn = ua_fail;
  } else {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, cmd->server,
		 "Unrecognized value for WebauthnIfUnauthn: '%s'", arg);
  }    
  return NULL;
}


static const char *webauthn_set_session_path(cmd_parms *cmd, void *cfg, const char *arg)
{
  config.session_path = apr_pstrdup(cmd->pool, arg);
  return NULL;
}

static const char *webauthn_set_verify_ssl_host(cmd_parms *cmd, void *cfg, const char *arg)
{
  /* In curl: 2 means verify hostname matches, 0 means don't */
  config.verify_ssl_host = ((strcasecmp(arg, "off") == 0) ? VERIFY_SSL_HOST_OFF : VERIFY_SSL_HOST_ON);
  return NULL;
}

static const char *webauthn_set_max_cache_seconds(cmd_parms *cmd, void *cfg, const char *arg)
{
  config.max_cache_seconds = atoi(arg);
  return NULL;
}

static group_alias *clone_group_alias(apr_pool_t *pool, const group_alias *old) {
  group_alias *new = (group_alias *)apr_pcalloc(pool, sizeof(group_alias));
  new->alias = apr_pstrdup(pool, old->alias);
  new->group = apr_pstrdup(pool, old->group);
  new->verify = old->verify;
  return new;
}
						

static const char *webauthn_add_group_alias(cmd_parms *cmd, void *cfg, const char *alias, const char *group, const char *verify)
{
  group_alias *new_alias = (group_alias *)apr_pcalloc(cmd->pool, sizeof(group_alias));
  new_alias->verify = 1;
  if (verify) {
    if (apr_strnatcasecmp(verify, NOVERIFY_STRING) == 0) {
      new_alias->verify = 0;
    } else if (apr_strnatcasecmp(verify, VERIFY_STRING) != 0) {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, cmd->server,
		   "Not adding group alias: unexpected parameter '%s' (expecting '%s' or '%s') in file %s, line %u",
		   verify, VERIFY_STRING, NOVERIFY_STRING, cmd->config_file->name, cmd->config_file->line_number);
      return NULL;
    }
  }
  new_alias->alias = apr_pstrdup(cmd->pool, alias);
  new_alias->group = apr_pstrdup(cmd->pool, group);
  if (cfg == NULL) {
    add_managed_hash_entry(config.alias_hash, new_alias->alias, new_alias);
  } else {
    webauthn_local_config *lcfg = (webauthn_local_config *)cfg;
    add_managed_hash_entry(lcfg->alias_hash, new_alias->alias, new_alias);    
  }
  return NULL;
}

static managed_hash *create_managed_hash(apr_pool_t *pool)
{
  managed_hash *mhash = (managed_hash *)apr_pcalloc(pool, sizeof(managed_hash));
  mhash->hash = apr_hash_make(pool);
  mhash->hash_pool_parent = pool;
  apr_thread_rwlock_create(&(mhash->hash_lock), pool);
  return mhash;
}

static managed_hash *create_alias_overlay(apr_pool_t *pool, apr_hash_t *overlay, apr_hash_t *base)
{
  managed_hash *mhash = (managed_hash *)apr_pcalloc(pool, sizeof(managed_hash));
  mhash->hash = apr_hash_make(pool);
  char *key;
  const group_alias *value;
  apr_hash_index_t *entry;

  /* Add all "overlay" entries */
  for (entry = apr_hash_first(pool, overlay); entry; entry = apr_hash_next(entry)) {
    apr_hash_this(entry, (void *)&key, NULL, (void *)&value);
    group_alias *alias = clone_group_alias(pool, value);
    apr_hash_set(mhash->hash, alias->alias, APR_HASH_KEY_STRING, alias);
  }
  /* Add "base" entries whose key hasn't already been added */
  for (entry = apr_hash_first(pool, base); entry; entry = apr_hash_next(entry)) {
    apr_hash_this(entry, (void *)&key, NULL, (void *)&value);
    if (apr_hash_get(mhash->hash, key, APR_HASH_KEY_STRING) == NULL) {
      group_alias *alias = clone_group_alias(pool, value);
      apr_hash_set(mhash->hash, alias->alias, APR_HASH_KEY_STRING, alias);
    }
  }
  mhash->hash_pool_parent = pool;
  apr_thread_rwlock_create(&(mhash->hash_lock), pool);
  return mhash;
}


static int webauthn_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{
  config.session_path = NULL;
  config.login_path = NULL;
  config.verify_ssl_host = VERIFY_SSL_HOST_ON;
  config.cookie_name = "webauthn";
  curl_global_init(CURL_GLOBAL_SSL);
  config.session_hash = create_managed_hash(pconf);
  config.alias_hash = create_managed_hash(pconf);
  config.max_cache_seconds = -1;
  return OK;
}

static size_t webauthn_curl_write_callback(char *indata, size_t size, size_t nitems, void *buffer)
{
  webauthn_http_data *d = (webauthn_http_data *)buffer;
  size_t insize = size * nitems;
  char *mydata;
  if ((mydata = (char *)apr_pcalloc(d->pool, insize + 1)) == NULL) {
    return(CURL_READFUNC_ABORT);
  }
  memcpy(mydata, indata, insize);
  mydata[insize] = '\0';
  d->segments[d->current_data_index].data = mydata;
  d->segments[d->current_data_index++].size = insize;
  return(insize);
}

static char *consolidate_segments(webauthn_http_data *data) {
  if (data->current_data_index == 1) {
    return data->segments[0].data;
  }
  int total_size = 0;
  for (int i = 0; i < data->current_data_index; i++) {
    total_size += data->segments[i].size;
  }
  char *str = (char *)apr_palloc(data->pool, total_size+1);
  char *s = str;
  for (int i = 0; i < data->current_data_index; i++) {
    memcpy(s, data->segments[i].data, data->segments[i].size);
    s+=data->segments[i].size;
  }
  *s = '\0';
  return(str);
}

static void fill_group_from_json(json_object *jobj, webauthn_group *group) {
  json_object_object_foreach(jobj, key, val) {
    if (strcmp(key, "id") == 0 && json_object_is_type(val, json_type_string)) {
      group->id = json_object_get_string(val);
    } else if (strcmp(key, "display_name") == 0 && json_object_is_type(val, json_type_string)) {
      group->display_name = json_object_get_string(val);
    }
  }
}

static webauthn_user *make_temp_user_from_json(json_object *jobj, request_rec *r) {
  webauthn_user *user = (webauthn_user *)apr_pcalloc(r->pool, sizeof(webauthn_user));
  json_object_object_foreach(jobj, key, val) {
    if (strcmp(key, "id") == 0 && json_object_is_type(val, json_type_string)) {
      user->id = json_object_get_string(val);
    } else if (strcmp(key, "display_name") == 0 && json_object_is_type(val, json_type_string)) {
      user->display_name = json_object_get_string(val);
    } else if (strcmp(key, "full_name") == 0 && json_object_is_type(val, json_type_string)) {
      user->full_name = json_object_get_string(val);
    } else if (strcmp(key, "email") == 0 && json_object_is_type(val, json_type_string)) {
      user->email = json_object_get_string(val);
    }
  }
  return(user->id ? user : NULL);
}

static webauthn_group *get_groups_from_json_array(json_object *jobj, request_rec *r) {
  int len = json_object_array_length(jobj);
  webauthn_group *groups = (webauthn_group *)apr_pcalloc(r->pool, (len + 1) * sizeof(webauthn_group));
  for (int i = 0; i < len; i++) {
    json_object *child = json_object_array_get_idx(jobj, i);
    fill_group_from_json(child, &groups[i]);
  }
  return(groups);
}


static void *create_local_conf(apr_pool_t *pool, char *context) {
  context = context ? context : "(undefined context)";
  webauthn_local_config *cfg = apr_pcalloc(pool, sizeof(webauthn_local_config));
  cfg->context = apr_pstrdup(pool, context);
  cfg->pool = pool;
  cfg->alias_hash = create_managed_hash(pool);
  cfg->if_unauthn = ua_unset;
  return cfg;
}

static void *merge_local_conf(apr_pool_t *pool, void *parent_cfg, void *child_cfg) {
  webauthn_local_config *parent = (webauthn_local_config *)parent_cfg;
  webauthn_local_config *child = (webauthn_local_config *)child_cfg;
  webauthn_local_config *merged = apr_pcalloc(pool, sizeof(webauthn_local_config));
  merged->context = "merged configuration";
  merged->pool = pool;
  merged->alias_hash = create_alias_overlay(pool, child->alias_hash->hash, parent->alias_hash->hash);
  merged->if_unauthn = (child->if_unauthn == ua_unset ? parent->if_unauthn : child->if_unauthn);
  return merged;
}


static multi_codes *do_multi_perform(CURL *curl, request_rec *r)
{
  CURLM *multi = curl_multi_init();
  curl_multi_add_handle(multi, curl);
  int still_running = 1;
  multi_codes *codes = apr_pcalloc(r->pool, sizeof(multi_codes));

  do {
    int numfds;
    codes->mcode = curl_multi_perform(multi, &still_running);
    if (codes->mcode != CURLM_OK) {
      goto end;
    }

    codes->mcode = curl_multi_wait(multi, NULL, 0, 1000, &numfds);
    if (codes->mcode != CURLM_OK) {
      goto end;
    }
    
    /* 'numfds' being zero means either a timeout or no file descriptors to
       wait for. */

    if(!numfds) {
	usleep(100000); /* sleep 100 milliseconds */ 
    }
  } while (still_running);

  CURLMsg *m;
  do {
    int msgq = 0;
    m = curl_multi_info_read(multi, &msgq);
    if(m && (m->msg == CURLMSG_DONE) && (m->easy_handle == curl)) {
      codes->ccode = m->data.result;
    }
  } while(m);

 end:
  curl_multi_remove_handle(multi, curl);
  return(codes);
}

static CURLcode do_simple_perform(CURL *curl) {
  return curl_easy_perform(curl);
};


static webauthn_group *group_from_list(const char *id, webauthn_group *ids) {
  if (id == 0 || ids == 0) {
    return(0);
  }
  for (int i = 0; ids[i].id; i++) {
    if (strcmp(id, ids[i].id) == 0) {
      return(&(ids[i]));
    }
  }
  return(0);
}


static authz_status webauthn_group_check_authorization(request_rec *r, const char *require_args, const void *parsed_require_args)
{
  webauthn_local_config *local_config = (webauthn_local_config *) ap_get_module_config(r->per_dir_config, &webauthn_module);
  ap_expr_info_t *expr = (ap_expr_info_t *)parsed_require_args;
  char time_string[APR_CTIME_LEN];
  apr_time_t now = apr_time_now();
  apr_ctime(time_string, now);
  const char *err = NULL;
  const char *groups_string = ap_expr_str_exec(r, expr, &err);

  managed_hash *group_alias_hash = local_config->alias_hash;

  session_info *sinfo = find_or_create_session_info(r, local_config);

  if (sinfo == 0) {
    return (AUTHZ_DENIED_NO_USER);
  }

  set_request_vals(r, sinfo);
  
  const char *desired_group = NULL;
  while ((desired_group = ap_getword_conf(r->pool, &groups_string)) && desired_group[0]) {
    if (group_from_list(desired_group, sinfo->groups)) {
      return(AUTHZ_GRANTED);
    }

    group_alias *aliased_group;
    if ((aliased_group = get_managed_hash_entry(group_alias_hash, desired_group)) != 0) {
      webauthn_group *found_group;
      if ((found_group = group_from_list(aliased_group->group, sinfo->groups)) != 0) {
	if (! aliased_group->verify) {
	  return(AUTHZ_GRANTED);
	}
	if (found_group->display_name && (strcmp(aliased_group->alias, found_group->display_name) == 0)) {
	  return(AUTHZ_GRANTED);
	} else {
	  ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
			"Group alias verify failed: display_name for '%s' was '%s' in credential, not '%s'",
			found_group->id, (found_group->display_name ? found_group->display_name : "(null)"), aliased_group->alias);
	}
      }
    }
  }

  return(AUTHZ_DENIED);
}

static void *get_managed_hash_entry(managed_hash *mhash, const char *key) {
  apr_thread_rwlock_rdlock(mhash->hash_lock);
  void *data = (session_info *)apr_hash_get(mhash->hash, key, APR_HASH_KEY_STRING);
  apr_thread_rwlock_unlock(mhash->hash_lock);
  return(data);
}  
    
static session_info *get_cached_session_info(const char *sessionid)
{
  return (session_info *)get_managed_hash_entry(config.session_hash, sessionid);
}

static void add_managed_hash_entry(managed_hash *mhash, const char *key, void *data) {
  apr_thread_rwlock_wrlock(mhash->hash_lock);
  apr_hash_set(mhash->hash, key, APR_HASH_KEY_STRING, data);
  apr_thread_rwlock_unlock(mhash->hash_lock);
}

static void cache_sessioninfo(session_info *sinfo, request_rec *r)
{
  if (config.max_cache_seconds) {
    if (sinfo) {
      char ts[APR_CTIME_LEN];
      apr_ctime(ts, sinfo->timeout);
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "cache: adding session %s wih timeout %s", sinfo->sessionid, ts);
      add_managed_hash_entry(config.session_hash, sinfo->sessionid, sinfo);
    }
  }
}

static int valid_unexpired_session(session_info *sinfo)
{
  return (sinfo && (apr_time_now() < sinfo->timeout));
}

static void delete_managed_hash_entry(managed_hash *mhash, const char *key, apr_pool_t *data_pool) {
  apr_thread_rwlock_wrlock(mhash->hash_lock);
  apr_hash_set(mhash->hash, key, APR_HASH_KEY_STRING, NULL);
  apr_thread_rwlock_unlock(mhash->hash_lock);
  apr_pool_destroy(data_pool);
}

static void delete_cached_session_info(session_info *sinfo)
{
  if (sinfo) {
    delete_managed_hash_entry(config.session_hash, sinfo->sessionid, sinfo->pool);
  }
}

static const char *webauthn_parse_config(cmd_parms *cmd, const char *require_line,
					 const void **parsed_require_line)
{
  const char *expr_err = NULL;
  ap_expr_info_t *expr;
  
  expr = ap_expr_parse_cmd(cmd, require_line, AP_EXPR_FLAG_STRING_RESULT,
			   &expr_err, NULL);
  
  if (expr_err)
    return apr_pstrcat(cmd->temp_pool,
		       "Cannot parse expression in require line: ",
		       expr_err, NULL);
  
  *parsed_require_line = expr;
  
  return NULL;
}
