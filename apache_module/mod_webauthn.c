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
#include <json/json.h>
#include <httpd/util_cookies.h>
#include <apr_time.h>
#include <unistd.h>

#define WEBAUTHN_GROUP "webauthn-group"
#define WEBAUTHN_SESSION_BASE64 "WEBAUTHN_SESSION_BASE64"
/* These next two are defined by curl */
#define VERIFY_SSL_HOST_OFF 0
#define VERIFY_SSL_HOST_ON 2

#define WEBAUTHN_DEFAULT_CACHE_SECONDS -1


static void register_hooks(apr_pool_t *pool);
static int webauthn_check_user_id(request_rec * r);
const char *webauthn_set_login_path(cmd_parms *cmd, void *cfg, const char *arg);
const char *webauthn_set_session_path(cmd_parms *cmd, void *cfg, const char *arg);
const char *webauthn_set_verify_ssl_host(cmd_parms *cmd, void *cfg, const char *arg);
const char *webauthn_set_cookie_name(cmd_parms *cmd, void *cfg, const char *arg);
static int webauthn_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp);
static size_t webauthn_curl_write_callback(char *indata, size_t size, size_t nitems, void *buffer);
static void *create_local_conf(apr_pool_t *pool, char *context);
static CURLcode do_simple_perform(CURL *curl);
static authz_status webauthn_group_check_authorization(request_rec *r, const char *require_args, const void *parsed_require_args);
const char *webauthn_set_max_cache_seconds(cmd_parms *cmd, void *cfg, const char *arg);
static const char *webauthn_parse_config(cmd_parms *cmd, const char *require_line, const void **parsed_require_line);

typedef struct {
  char *session_path;
  char *login_path;
  char *cookie_name;
  apr_hash_t *session_hash;
  apr_pool_t *hash_pool_parent;
  apr_thread_rwlock_t *hash_lock;
  int max_cache_seconds;
  int verify_ssl_host;
} webauthn_config;


static webauthn_config config;

typedef struct {
  char *context;
  apr_pool_t *pool;
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

static session_info *get_cached_session_info(const char *sessionid);
static session_info *make_session_info(request_rec *r, apr_pool_t *parent_pool, const char *sessionid, char *json_string);
static session_info *webauthn_make_session_info_from_scratch(request_rec * r, webauthn_local_config *local_config);
static void cache_sessioninfo(session_info *sinfo);
static int valid_unexpired_session(session_info *sinfo);
static void delete_cached_session_info(session_info *sinfo);
static void set_request_vals(request_rec *r, session_info *sinfo);

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
    { NULL }
  };

module AP_MODULE_DECLARE_DATA webauthn_module =
  {
    STANDARD20_MODULE_STUFF,
    create_local_conf,
    NULL,
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

static int webauthn_check_user_id(request_rec * r)
{
  int retval = HTTP_UNAUTHORIZED;
  webauthn_local_config *local_config = (webauthn_local_config *) ap_get_module_config(r->per_dir_config, &webauthn_module);
  session_info *sinfo = webauthn_make_session_info_from_scratch(r, local_config);
  
  if (sinfo) {
    set_request_vals(r, sinfo);
    retval = OK;
  }
  return(retval);
}

static void set_request_vals(request_rec *r, session_info *sinfo) {
  if (sinfo->user) {
    cache_sessioninfo(sinfo);
    r->user = apr_pstrdup(r->pool, sinfo->user->id);
    if (r->subprocess_env == NULL) {
      r->subprocess_env = apr_table_make(r->pool, 1);
    }
    apr_table_set(r->subprocess_env, WEBAUTHN_SESSION_BASE64, apr_pstrdup(r->pool, sinfo->base64_session_string));
  }
}

static size_t webauthn_read_noop(char *buffer, size_t size, size_t nitems, void *instream) {
  size_t len=size*nitems;
  if (len > 0) {
    memset(buffer, 0, len);
  }
  return(len);
}

static session_info *webauthn_make_session_info_from_scratch(request_rec * r, webauthn_local_config *local_config)
{
  int debug = 0;
  session_info *sinfo = 0;

  const char *session_uri=apr_psprintf(r->pool, "https://%s%s", r->hostname, config.session_path);
  const char *login_uri=apr_psprintf(r->pool, "https://%s%s?do_redirect=true&referrer=%s",
				     r->hostname, config.login_path,
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
    sinfo = make_session_info(r, config.hash_pool_parent, sessionid, json_string);
  }
 end:
  if (session_curl) {
    curl_easy_cleanup(session_curl);
  }
  if (sinfo == NULL) {
    ap_internal_redirect(login_uri, r);
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
  curl_easy_setopt(curl, CURLOPT_UPLOAD, 0L);
  curl_easy_setopt(curl, CURLOPT_READFUNCTION, webauthn_read_noop);
  curl_easy_setopt(curl, CURLOPT_READDATA, NULL);
  long dummy_size = 0L;
  curl_easy_setopt(curl, CURLOPT_INFILESIZE, &dummy_size);
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

apr_time_t make_session_timeout(int server_seconds) {
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
      if (sess->groups[i].display_name) {
	sess->groups[i].display_name = apr_pstrdup(pool, groups[i].display_name);
      }
    }
  }
  return(sess);
}

const char *webauthn_set_login_path(cmd_parms *cmd, void *cfg, const char *arg)
{
  config.login_path = strdup(arg);
  return NULL;
}

const char *webauthn_set_cookie_name(cmd_parms *cmd, void *cfg, const char *arg)
{
  config.cookie_name = strdup(arg);
  return NULL;
}


const char *webauthn_set_session_path(cmd_parms *cmd, void *cfg, const char *arg)
{
  config.session_path = strdup(arg);
  return NULL;
}

const char *webauthn_set_verify_ssl_host(cmd_parms *cmd, void *cfg, const char *arg)
{
  /* In curl: 2 means verify hostname matches, 0 means don't */
  config.verify_ssl_host = ((strcasecmp(arg, "off") == 0) ? VERIFY_SSL_HOST_OFF : VERIFY_SSL_HOST_ON);
  return NULL;
}

const char *webauthn_set_max_cache_seconds(cmd_parms *cmd, void *cfg, const char *arg)
{
  config.max_cache_seconds = atoi(arg);
  return NULL;
}


static int webauthn_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{
  config.session_path = NULL;
  config.login_path = NULL;
  config.verify_ssl_host = VERIFY_SSL_HOST_ON;
  config.cookie_name = "ermrest";
  curl_global_init(CURL_GLOBAL_SSL);
  config.session_hash = apr_hash_make(pconf);
  config.hash_pool_parent = pconf;
  apr_thread_rwlock_create(&config.hash_lock, pconf);
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
  return cfg;
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


static int in_id_list(const char *id, webauthn_group *ids) {
  if (id == 0 || ids == 0) {
    return(0);
  }
  for (int i = 0; ids[i].id; i++) {
    if (strcmp(id, ids[i].id) == 0) {
      return(1);
    }
  }
  return(0);
}


static authz_status webauthn_group_check_authorization(request_rec *r, const char *require_args, const void *parsed_require_args)
{
  webauthn_local_config *local_config = (webauthn_local_config *) ap_get_module_config(r->per_dir_config, &webauthn_module);
  ap_expr_info_t *expr = (ap_expr_info_t *)parsed_require_args;
  const char *sessionid = 0;
  session_info *sinfo = 0;
  char time_string[APR_CTIME_LEN];
  apr_time_t now = apr_time_now();
  apr_ctime(time_string, now);
  ap_cookie_read(r, config.cookie_name, &sessionid, 0);
  if (sessionid != NULL) {
    sinfo = get_cached_session_info(sessionid);
  }

  if (! valid_unexpired_session(sinfo)) {
    delete_cached_session_info(sinfo);
    sinfo = 0;
  }

  if (sinfo == NULL) {
    sinfo = webauthn_make_session_info_from_scratch(r, local_config);
    
    if (sinfo && sinfo->user) {
      set_request_vals(r, sinfo);
    }
  }
  if (sinfo) {
    char ts[APR_CTIME_LEN];
    apr_ctime(ts, sinfo->timeout);
  }
  const char *err = NULL;
  const char *groups_string = ap_expr_str_exec(r, expr, &err);

  if (sinfo) {
    int i = 0;
    const char *group = NULL;
    while ((group = ap_getword_conf(r->pool, &groups_string)) && group[0]) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "checking group %d: %s", i, group);
      i++;
      if (in_id_list(group, sinfo->groups)) {
	return(AUTHZ_GRANTED);
      }
    }
  }

  return(AUTHZ_DENIED);
}
    
static session_info *get_cached_session_info(const char *sessionid)
{
  apr_thread_rwlock_rdlock(config.hash_lock);
  session_info *sinfo = (session_info *)apr_hash_get(config.session_hash, sessionid, APR_HASH_KEY_STRING);
  apr_thread_rwlock_unlock(config.hash_lock);
  return(sinfo);
}

static void cache_sessioninfo(session_info *sinfo)
{
  if (config.max_cache_seconds) {
    apr_thread_rwlock_wrlock(config.hash_lock);
    apr_hash_set(config.session_hash, sinfo->sessionid, APR_HASH_KEY_STRING, sinfo);
    apr_thread_rwlock_unlock(config.hash_lock);
  }
}

static int valid_unexpired_session(session_info *sinfo)
{
  return (sinfo && (apr_time_now() < sinfo->timeout));
}

static void delete_cached_session_info(session_info *sinfo)
{
  if (sinfo) {
    apr_thread_rwlock_wrlock(config.hash_lock);
    apr_hash_set(config.session_hash, sinfo->sessionid, APR_HASH_KEY_STRING, NULL);
    apr_thread_rwlock_unlock(config.hash_lock);
    apr_pool_destroy(sinfo->pool);
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
