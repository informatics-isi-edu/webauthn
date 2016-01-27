SET search_path = webauthn2_goauth;
--
-- Name: attribute; Type: TABLE; Schema: webauthn2_goauth; Owner: -; Tablespace: 
--

CREATE TABLE IF NOT EXISTS attribute (
    aid serial primary key,
    attribute text unique
);

--
-- Name: nestedattribute; Type: TABLE; Schema: webauthn2_goauth; Owner: -; Tablespace: 
--

CREATE TABLE IF NOT EXISTS nestedattribute (
    child integer references attribute(aid) on delete cascade,
    parent integer references attribute(aid) on delete cascade,
    UNIQUE (child, parent)
);


--
-- Name: userattribute; Type: TABLE; Schema: webauthn2_goauth; Owner: -; Tablespace: 
--

CREATE TABLE IF NOT EXISTS userattribute (
    username text,
    aid integer references attribute(aid) on delete cascade,
    unique(username, aid)
);


--
-- Name: attributesummary; Type: VIEW; Schema: webauthn2_goauth; Owner: -
--
CREATE or replace VIEW attributesummary AS
  WITH RECURSIVE taa(aid, taid) AS (
      SELECT aid, aid FROM attribute
    UNION
      SELECT base.aid, recur.parent
      FROM taa AS base
      JOIN nestedattribute AS recur ON (base.taid = recur.child)
  ), 

  tua2 AS (
    SELECT ua.username AS username, array_agg(DISTINCT a.attribute) AS attributes
    FROM userattribute AS ua 
    JOIN taa ON (ua.aid = taa.aid)
    JOIN attribute AS a ON (taa.taid = a.aid)
    GROUP BY ua.username
  ), 

  taa2 AS (
    SELECT taa.aid AS aid, array_agg(a.attribute) AS attributes
    FROM taa 
    JOIN attribute AS a ON (taa.taid = a.aid)
    GROUP BY taa.aid
  ), 

  aa2 AS (
    SELECT aa.child AS aid, array_agg(DISTINCT a.attribute) AS attributes 
    FROM (SELECT * FROM nestedattribute UNION SELECT aid, aid FROM attribute) AS aa
    JOIN attribute AS a ON (aa.parent = a.aid)
    GROUP BY aa.child
  ), 

  ua2 AS (
    SELECT ua.username, array_agg(DISTINCT a.attribute) AS attributes 
    FROM userattribute AS ua
    JOIN attribute AS a ON (ua.aid = a.aid)
    GROUP BY ua.username
  )

  SELECT 
    ua2.username AS name,
    'client' AS type,
    ua2.attributes AS direct_attributes,
    tua2.attributes AS all_attributes
  FROM ua2
  LEFT OUTER JOIN tua2 ON (ua2.username = tua2.username)

UNION

  SELECT 
    a.attribute AS name,
    'attribute' AS type,
    aa2.attributes AS direct_attributes,
    taa2.attributes AS all_attributes
  FROM attribute a
  LEFT OUTER JOIN aa2 ON (a.aid = aa2.aid)
  LEFT OUTER JOIN taa2 ON (a.aid = taa2.aid)

;

--
-- Name: webauthn2_version_attribute; Type: VIEW; Schema: webauthn2_goauth; Owner: -
--

CREATE OR REPLACE VIEW webauthn2_version_attribute AS
 SELECT 1 AS major,
    0 AS minor;




