--
-- PostgreSQL database dump
--

\restrict TjS7Z9fh9rZmCNc6d5VSlespCRhwQfdzQMFaadM4pHNYPvW0oJaW4ci6NTwI3Lo

-- Dumped from database version 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)
-- Dumped by pg_dump version 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pg_trgm; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;


--
-- Name: EXTENSION pg_trgm; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pg_trgm IS 'text similarity measurement and index searching based on trigrams';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: Log_Source; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public."Log_Source" (
    source_id integer NOT NULL,
    source_name character varying(255),
    source_path character varying(255)
);


ALTER TABLE public."Log_Source" OWNER TO postgres;

--
-- Name: Log_Source_source_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public."Log_Source_source_id_seq"
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public."Log_Source_source_id_seq" OWNER TO postgres;

--
-- Name: Log_Source_source_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public."Log_Source_source_id_seq" OWNED BY public."Log_Source".source_id;


--
-- Name: alert_occurrences; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.alert_occurrences (
    id integer NOT NULL,
    alert_id_fk integer,
    occurred_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    fk_msg_id integer,
    source_ip inet,
    details text
);


ALTER TABLE public.alert_occurrences OWNER TO postgres;

--
-- Name: alert_occurrences_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.alert_occurrences_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.alert_occurrences_id_seq OWNER TO postgres;

--
-- Name: alert_occurrences_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.alert_occurrences_id_seq OWNED BY public.alert_occurrences.id;


--
-- Name: alerts; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.alerts (
    id integer NOT NULL,
    alert_id character(20) NOT NULL,
    alert_type character varying(50) NOT NULL,
    severity character varying(20) NOT NULL,
    is_active boolean DEFAULT true,
    count integer DEFAULT 0,
    source_ip inet,
    acknowledged_time timestamp without time zone,
    admin_note text,
    fk_msg_id integer
);


ALTER TABLE public.alerts OWNER TO postgres;

--
-- Name: alerts_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.alerts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.alerts_id_seq OWNER TO postgres;

--
-- Name: alerts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.alerts_id_seq OWNED BY public.alerts.id;


--
-- Name: archive_audit_log; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.archive_audit_log (
    id integer NOT NULL,
    occurred_at timestamp with time zone DEFAULT now(),
    action character varying(50) NOT NULL,
    performed_by character varying(100),
    user_id integer,
    partition_date date,
    table_name character varying(100),
    manifest_id integer,
    detail jsonb DEFAULT '{}'::jsonb,
    ip_address inet,
    success boolean DEFAULT true,
    error_msg text
);


ALTER TABLE public.archive_audit_log OWNER TO postgres;

--
-- Name: archive_audit_log_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.archive_audit_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.archive_audit_log_id_seq OWNER TO postgres;

--
-- Name: archive_audit_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.archive_audit_log_id_seq OWNED BY public.archive_audit_log.id;


--
-- Name: archive_manifest; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.archive_manifest (
    id integer NOT NULL,
    partition_date date NOT NULL,
    table_name character varying(100) NOT NULL,
    file_path text NOT NULL,
    row_count bigint DEFAULT 0 NOT NULL,
    file_size_bytes bigint DEFAULT 0 NOT NULL,
    sha256_hash character(64),
    compression character varying(20) DEFAULT 'zstd'::character varying,
    encrypted boolean DEFAULT false,
    state character varying(20) DEFAULT 'pending'::character varying,
    frozen boolean DEFAULT false,
    frozen_by character varying(100),
    frozen_reason text,
    frozen_at timestamp with time zone,
    partial boolean DEFAULT false,
    rows_exported bigint DEFAULT 0,
    rows_total bigint DEFAULT 0,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    verified_at timestamp with time zone,
    deleted_at timestamp with time zone,
    error_msg text,
    backend_type character varying(20),
    storage_config_id integer,
    CONSTRAINT archive_manifest_state_check CHECK (((state)::text = ANY (ARRAY[('pending'::character varying)::text, ('exporting'::character varying)::text, ('exported'::character varying)::text, ('verified'::character varying)::text, ('verify_failed'::character varying)::text, ('deleted_from_hot'::character varying)::text, ('failed'::character varying)::text])))
);


ALTER TABLE public.archive_manifest OWNER TO postgres;

--
-- Name: archive_manifest_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.archive_manifest_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.archive_manifest_id_seq OWNER TO postgres;

--
-- Name: archive_manifest_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.archive_manifest_id_seq OWNED BY public.archive_manifest.id;


--
-- Name: archive_policy; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.archive_policy (
    id integer DEFAULT 1 NOT NULL,
    enabled boolean DEFAULT false,
    hot_retention_days integer DEFAULT 90,
    cold_retention_days integer DEFAULT 1095,
    run_time time without time zone DEFAULT '02:00:00'::time without time zone,
    compression character varying(20) DEFAULT 'zstd'::character varying,
    encrypt_at_rest boolean DEFAULT false,
    verify_after_export boolean DEFAULT true,
    delete_after_verify boolean DEFAULT true,
    partial_export_behaviour character varying(20) DEFAULT 'keep'::character varying,
    storage_alert_threshold_gb integer DEFAULT 100,
    archive_messages boolean DEFAULT true,
    archive_alerts boolean DEFAULT true,
    archive_alert_occurrences boolean DEFAULT false,
    alerts_retention_days integer DEFAULT 365,
    updated_at timestamp with time zone DEFAULT now(),
    updated_by character varying(100),
    CONSTRAINT archive_policy_compression_check CHECK (((compression)::text = ANY (ARRAY[('snappy'::character varying)::text, ('zstd'::character varying)::text, ('none'::character varying)::text]))),
    CONSTRAINT archive_policy_id_check CHECK ((id = 1)),
    CONSTRAINT archive_policy_partial_export_behaviour_check CHECK (((partial_export_behaviour)::text = ANY (ARRAY[('keep'::character varying)::text, ('delete_exported'::character varying)::text])))
);


ALTER TABLE public.archive_policy OWNER TO postgres;

--
-- Name: archive_rehydration; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.archive_rehydration (
    id integer NOT NULL,
    date_from date NOT NULL,
    date_to date NOT NULL,
    tables text[] NOT NULL,
    state character varying(20) DEFAULT 'pending'::character varying,
    rows_imported bigint DEFAULT 0,
    started_by character varying(100),
    user_id integer,
    auto_release_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    completed_at timestamp with time zone,
    released_at timestamp with time zone,
    error_msg text,
    pid integer,
    partitions_total integer DEFAULT 0 NOT NULL,
    partitions_done integer DEFAULT 0 NOT NULL,
    CONSTRAINT archive_rehydration_state_check CHECK (((state)::text = ANY (ARRAY[('pending'::character varying)::text, ('running'::character varying)::text, ('active'::character varying)::text, ('releasing'::character varying)::text, ('released'::character varying)::text, ('failed'::character varying)::text, ('cancelled'::character varying)::text])))
);


ALTER TABLE public.archive_rehydration OWNER TO postgres;

--
-- Name: archive_rehydration_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.archive_rehydration_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.archive_rehydration_id_seq OWNER TO postgres;

--
-- Name: archive_rehydration_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.archive_rehydration_id_seq OWNED BY public.archive_rehydration.id;


--
-- Name: archive_schema_registry; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.archive_schema_registry (
    key character varying(200) NOT NULL,
    first_seen timestamp with time zone DEFAULT now(),
    last_seen timestamp with time zone DEFAULT now(),
    occurrence_count bigint DEFAULT 1,
    promoted boolean DEFAULT false,
    data_type character varying(20) DEFAULT 'string'::character varying,
    example_value text,
    source_parsers text[]
);


ALTER TABLE public.archive_schema_registry OWNER TO postgres;

--
-- Name: archive_storage_config; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.archive_storage_config (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    backend_type character varying(20) NOT NULL,
    is_active boolean DEFAULT false,
    config_json text DEFAULT '{}'::text NOT NULL,
    credentials_enc text,
    last_tested_at timestamp with time zone,
    last_test_ok boolean,
    last_test_msg text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT archive_storage_config_backend_type_check CHECK (((backend_type)::text = ANY (ARRAY[('local'::character varying)::text, ('sftp'::character varying)::text, ('s3'::character varying)::text])))
);


ALTER TABLE public.archive_storage_config OWNER TO postgres;

--
-- Name: archive_storage_config_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.archive_storage_config_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.archive_storage_config_id_seq OWNER TO postgres;

--
-- Name: archive_storage_config_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.archive_storage_config_id_seq OWNED BY public.archive_storage_config.id;


--
-- Name: calendar; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.calendar (
    data_id integer NOT NULL,
    date date,
    "time" time without time zone
);


ALTER TABLE public.calendar OWNER TO postgres;

--
-- Name: calendar_data_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.calendar_data_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.calendar_data_id_seq OWNER TO postgres;

--
-- Name: calendar_data_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.calendar_data_id_seq OWNED BY public.calendar.data_id;


--
-- Name: device; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.device (
    device_id integer NOT NULL,
    device_type character varying(255),
    device_name character varying(255),
    device_ip character varying(255),
    device_port integer
);


ALTER TABLE public.device OWNER TO postgres;

--
-- Name: device_device_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.device_device_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.device_device_id_seq OWNER TO postgres;

--
-- Name: device_device_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.device_device_id_seq OWNED BY public.device.device_id;


--
-- Name: login; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.login (
    user_id integer NOT NULL,
    username character varying(50) NOT NULL,
    email character varying(100) NOT NULL,
    password_hash text NOT NULL,
    role character varying(20) DEFAULT 'viewer'::character varying,
    is_active boolean DEFAULT true,
    is_verified boolean DEFAULT false,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone,
    last_login timestamp without time zone,
    failed_attempts integer DEFAULT 0,
    locked_until timestamp without time zone
);


ALTER TABLE public.login OWNER TO postgres;

--
-- Name: login_user_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.login_user_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.login_user_id_seq OWNER TO postgres;

--
-- Name: login_user_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.login_user_id_seq OWNED BY public.login.user_id;


--
-- Name: malicious_artifacts; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.malicious_artifacts (
    artifacts text NOT NULL,
    "interval" integer DEFAULT 0,
    severity character varying(10) DEFAULT 'mid'::character varying,
    added_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    source_url character varying(500),
    CONSTRAINT malicious_artifacts_severity_check CHECK (((severity)::text = ANY (ARRAY[('low'::character varying)::text, ('mid'::character varying)::text, ('high'::character varying)::text, ('critical'::character varying)::text])))
);


ALTER TABLE public.malicious_artifacts OWNER TO postgres;

--
-- Name: message; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.message (
    message_id integer NOT NULL,
    message_source integer,
    date integer,
    message text,
    log_source integer,
    device_id integer,
    process_id integer
);


ALTER TABLE public.message OWNER TO postgres;

--
-- Name: message_message_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.message_message_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.message_message_id_seq OWNER TO postgres;

--
-- Name: message_message_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.message_message_id_seq OWNED BY public.message.message_id;


--
-- Name: process; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.process (
    process_id integer NOT NULL,
    process_name character varying(255),
    pid integer
);


ALTER TABLE public.process OWNER TO postgres;

--
-- Name: process_process_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.process_process_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.process_process_id_seq OWNER TO postgres;

--
-- Name: process_process_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.process_process_id_seq OWNED BY public.process.process_id;


--
-- Name: special_messages; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.special_messages (
    case_id_fk integer,
    msg_id integer NOT NULL,
    message text,
    can_repeat boolean DEFAULT false,
    "order" integer
);


ALTER TABLE public.special_messages OWNER TO postgres;

--
-- Name: special_messages_msg_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.special_messages_msg_id_seq
    START WITH 10
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.special_messages_msg_id_seq OWNER TO postgres;

--
-- Name: special_messages_msg_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.special_messages_msg_id_seq OWNED BY public.special_messages.msg_id;


--
-- Name: use_cases; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.use_cases (
    case_id integer NOT NULL,
    case_name character varying NOT NULL,
    entity_field character varying(50) DEFAULT 'ip'::character varying,
    severity character varying(10) DEFAULT 'high'::character varying,
    CONSTRAINT use_cases_severity_check CHECK (((severity)::text = ANY (ARRAY[('low'::character varying)::text, ('mid'::character varying)::text, ('high'::character varying)::text, ('critical'::character varying)::text])))
);


ALTER TABLE public.use_cases OWNER TO postgres;

--
-- Name: use_cases_case_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.use_cases_case_id_seq
    START WITH 3
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.use_cases_case_id_seq OWNER TO postgres;

--
-- Name: use_cases_case_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.use_cases_case_id_seq OWNED BY public.use_cases.case_id;


--
-- Name: user_permissions; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_permissions (
    user_id integer NOT NULL,
    can_create boolean DEFAULT false,
    can_read boolean DEFAULT true,
    can_update boolean DEFAULT false,
    can_delete boolean DEFAULT false,
    archive_role character varying(20) DEFAULT 'none'::character varying,
    CONSTRAINT user_permissions_archive_role_check CHECK (((archive_role)::text = ANY (ARRAY[('none'::character varying)::text, ('viewer'::character varying)::text, ('operator'::character varying)::text, ('administrator'::character varying)::text])))
);


ALTER TABLE public.user_permissions OWNER TO postgres;

--
-- Name: watcher_health; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.watcher_health (
    id integer NOT NULL,
    client_name character varying(150),
    source_ip character varying(45) NOT NULL,
    last_heartbeat_at timestamp with time zone DEFAULT now(),
    last_message_at timestamp with time zone,
    offline_threshold_minutes integer,
    is_online boolean DEFAULT true,
    marked_offline_at timestamp with time zone,
    alert_id_fk integer,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.watcher_health OWNER TO postgres;

--
-- Name: watcher_health_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.watcher_health_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.watcher_health_id_seq OWNER TO postgres;

--
-- Name: watcher_health_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.watcher_health_id_seq OWNED BY public.watcher_health.id;


--
-- Name: watcher_health_settings; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.watcher_health_settings (
    id integer DEFAULT 1 NOT NULL,
    default_offline_threshold_minutes integer DEFAULT 5,
    check_interval_seconds integer DEFAULT 60,
    enabled boolean DEFAULT true,
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT watcher_health_settings_id_check CHECK ((id = 1))
);


ALTER TABLE public.watcher_health_settings OWNER TO postgres;

--
-- Name: Log_Source source_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public."Log_Source" ALTER COLUMN source_id SET DEFAULT nextval('public."Log_Source_source_id_seq"'::regclass);


--
-- Name: alert_occurrences id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alert_occurrences ALTER COLUMN id SET DEFAULT nextval('public.alert_occurrences_id_seq'::regclass);


--
-- Name: alerts id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alerts ALTER COLUMN id SET DEFAULT nextval('public.alerts_id_seq'::regclass);


--
-- Name: archive_audit_log id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_audit_log ALTER COLUMN id SET DEFAULT nextval('public.archive_audit_log_id_seq'::regclass);


--
-- Name: archive_manifest id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_manifest ALTER COLUMN id SET DEFAULT nextval('public.archive_manifest_id_seq'::regclass);


--
-- Name: archive_rehydration id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_rehydration ALTER COLUMN id SET DEFAULT nextval('public.archive_rehydration_id_seq'::regclass);


--
-- Name: archive_storage_config id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_storage_config ALTER COLUMN id SET DEFAULT nextval('public.archive_storage_config_id_seq'::regclass);


--
-- Name: calendar data_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.calendar ALTER COLUMN data_id SET DEFAULT nextval('public.calendar_data_id_seq'::regclass);


--
-- Name: device device_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.device ALTER COLUMN device_id SET DEFAULT nextval('public.device_device_id_seq'::regclass);


--
-- Name: login user_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.login ALTER COLUMN user_id SET DEFAULT nextval('public.login_user_id_seq'::regclass);


--
-- Name: message message_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message ALTER COLUMN message_id SET DEFAULT nextval('public.message_message_id_seq'::regclass);


--
-- Name: process process_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.process ALTER COLUMN process_id SET DEFAULT nextval('public.process_process_id_seq'::regclass);


--
-- Name: special_messages msg_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.special_messages ALTER COLUMN msg_id SET DEFAULT nextval('public.special_messages_msg_id_seq'::regclass);


--
-- Name: use_cases case_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.use_cases ALTER COLUMN case_id SET DEFAULT nextval('public.use_cases_case_id_seq'::regclass);


--
-- Name: watcher_health id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.watcher_health ALTER COLUMN id SET DEFAULT nextval('public.watcher_health_id_seq'::regclass);


--
-- Name: Log_Source Log_Source_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public."Log_Source"
    ADD CONSTRAINT "Log_Source_pkey" PRIMARY KEY (source_id);


--
-- Name: alert_occurrences alert_occurrences_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alert_occurrences
    ADD CONSTRAINT alert_occurrences_pkey PRIMARY KEY (id);


--
-- Name: alerts alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_pkey PRIMARY KEY (id);


--
-- Name: archive_audit_log archive_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_audit_log
    ADD CONSTRAINT archive_audit_log_pkey PRIMARY KEY (id);


--
-- Name: archive_manifest archive_manifest_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_manifest
    ADD CONSTRAINT archive_manifest_pkey PRIMARY KEY (id);


--
-- Name: archive_policy archive_policy_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_policy
    ADD CONSTRAINT archive_policy_pkey PRIMARY KEY (id);


--
-- Name: archive_rehydration archive_rehydration_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_rehydration
    ADD CONSTRAINT archive_rehydration_pkey PRIMARY KEY (id);


--
-- Name: archive_schema_registry archive_schema_registry_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_schema_registry
    ADD CONSTRAINT archive_schema_registry_pkey PRIMARY KEY (key);


--
-- Name: archive_storage_config archive_storage_config_name_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_storage_config
    ADD CONSTRAINT archive_storage_config_name_key UNIQUE (name);


--
-- Name: archive_storage_config archive_storage_config_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_storage_config
    ADD CONSTRAINT archive_storage_config_pkey PRIMARY KEY (id);


--
-- Name: calendar calendar_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.calendar
    ADD CONSTRAINT calendar_pkey PRIMARY KEY (data_id);


--
-- Name: device device_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.device
    ADD CONSTRAINT device_pkey PRIMARY KEY (device_id);


--
-- Name: login login_email_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.login
    ADD CONSTRAINT login_email_key UNIQUE (email);


--
-- Name: login login_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.login
    ADD CONSTRAINT login_pkey PRIMARY KEY (user_id);


--
-- Name: login login_username_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.login
    ADD CONSTRAINT login_username_key UNIQUE (username);


--
-- Name: message message_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message
    ADD CONSTRAINT message_pkey PRIMARY KEY (message_id);


--
-- Name: process process_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.process
    ADD CONSTRAINT process_pkey PRIMARY KEY (process_id);


--
-- Name: special_messages special_messages_pkey1; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.special_messages
    ADD CONSTRAINT special_messages_pkey1 PRIMARY KEY (msg_id);


--
-- Name: malicious_artifacts unique_artifact; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.malicious_artifacts
    ADD CONSTRAINT unique_artifact UNIQUE (artifacts);


--
-- Name: use_cases use_cases_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.use_cases
    ADD CONSTRAINT use_cases_pkey PRIMARY KEY (case_id);


--
-- Name: user_permissions user_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_permissions
    ADD CONSTRAINT user_permissions_pkey PRIMARY KEY (user_id);


--
-- Name: watcher_health watcher_health_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.watcher_health
    ADD CONSTRAINT watcher_health_pkey PRIMARY KEY (id);


--
-- Name: watcher_health_settings watcher_health_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.watcher_health_settings
    ADD CONSTRAINT watcher_health_settings_pkey PRIMARY KEY (id);


--
-- Name: archive_audit_log_action; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX archive_audit_log_action ON public.archive_audit_log USING btree (action);


--
-- Name: archive_audit_log_occurred_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX archive_audit_log_occurred_at ON public.archive_audit_log USING btree (occurred_at DESC);


--
-- Name: archive_audit_log_partition_date; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX archive_audit_log_partition_date ON public.archive_audit_log USING btree (partition_date);


--
-- Name: archive_manifest_date; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX archive_manifest_date ON public.archive_manifest USING btree (partition_date DESC);


--
-- Name: archive_manifest_partition_table; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX archive_manifest_partition_table ON public.archive_manifest USING btree (partition_date, table_name);


--
-- Name: archive_manifest_state; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX archive_manifest_state ON public.archive_manifest USING btree (state);


--
-- Name: archive_rehydration_state; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX archive_rehydration_state ON public.archive_rehydration USING btree (state);


--
-- Name: archive_storage_config_active; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX archive_storage_config_active ON public.archive_storage_config USING btree (is_active) WHERE (is_active = true);


--
-- Name: idx_alert_occurrences_alert_id_fk; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_alert_occurrences_alert_id_fk ON public.alert_occurrences USING btree (alert_id_fk);


--
-- Name: idx_alert_occurrences_fk_msg_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_alert_occurrences_fk_msg_id ON public.alert_occurrences USING btree (fk_msg_id);


--
-- Name: idx_alerts_fk_msg_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_alerts_fk_msg_id ON public.alerts USING btree (fk_msg_id);


--
-- Name: idx_calendar_data_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_calendar_data_id ON public.calendar USING btree (data_id);


--
-- Name: idx_calendar_data_time; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_calendar_data_time ON public.calendar USING btree (data_id, "time");


--
-- Name: idx_calendar_date; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_calendar_date ON public.calendar USING btree (date);


--
-- Name: idx_calendar_datetime_expr; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_calendar_datetime_expr ON public.calendar USING btree (((date + "time")));


--
-- Name: idx_device_device_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_device_device_id ON public.device USING btree (device_id);


--
-- Name: idx_log_source_source_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_log_source_source_id ON public."Log_Source" USING btree (source_id);


--
-- Name: idx_message_date; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_message_date ON public.message USING btree (date);


--
-- Name: idx_message_device_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_message_device_id ON public.message USING btree (device_id);


--
-- Name: idx_message_log_source; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_message_log_source ON public.message USING btree (log_source);


--
-- Name: idx_message_message_search; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_message_message_search ON public.message USING gin (to_tsvector('english'::regconfig, message));


--
-- Name: idx_message_message_trgm; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_message_message_trgm ON public.message USING gin (message public.gin_trgm_ops);


--
-- Name: watcher_health_is_online; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX watcher_health_is_online ON public.watcher_health USING btree (is_online);


--
-- Name: watcher_health_source_ip; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX watcher_health_source_ip ON public.watcher_health USING btree (source_ip);


--
-- Name: alert_occurrences alert_occurrences_alert_id_fk_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alert_occurrences
    ADD CONSTRAINT alert_occurrences_alert_id_fk_fkey FOREIGN KEY (alert_id_fk) REFERENCES public.alerts(id) ON DELETE CASCADE;


--
-- Name: alert_occurrences alert_occurrences_fk_msg_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alert_occurrences
    ADD CONSTRAINT alert_occurrences_fk_msg_id_fkey FOREIGN KEY (fk_msg_id) REFERENCES public.message(message_id);


--
-- Name: archive_audit_log archive_audit_log_manifest_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_audit_log
    ADD CONSTRAINT archive_audit_log_manifest_id_fkey FOREIGN KEY (manifest_id) REFERENCES public.archive_manifest(id) ON DELETE SET NULL;


--
-- Name: special_messages caseid; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.special_messages
    ADD CONSTRAINT caseid FOREIGN KEY (case_id_fk) REFERENCES public.use_cases(case_id);


--
-- Name: alerts fk_message; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT fk_message FOREIGN KEY (fk_msg_id) REFERENCES public.message(message_id);


--
-- Name: message message_date_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message
    ADD CONSTRAINT message_date_fkey FOREIGN KEY (date) REFERENCES public.calendar(data_id);


--
-- Name: message message_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message
    ADD CONSTRAINT message_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.device(device_id);


--
-- Name: message message_log_source_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message
    ADD CONSTRAINT message_log_source_fkey FOREIGN KEY (log_source) REFERENCES public."Log_Source"(source_id);


--
-- Name: message message_message_source_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message
    ADD CONSTRAINT message_message_source_fkey FOREIGN KEY (message_source) REFERENCES public."Log_Source"(source_id);


--
-- Name: message message_process_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message
    ADD CONSTRAINT message_process_id_fkey FOREIGN KEY (process_id) REFERENCES public.process(process_id);


--
-- Name: user_permissions user_permissions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_permissions
    ADD CONSTRAINT user_permissions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.login(user_id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict TjS7Z9fh9rZmCNc6d5VSlespCRhwQfdzQMFaadM4pHNYPvW0oJaW4ci6NTwI3Lo

