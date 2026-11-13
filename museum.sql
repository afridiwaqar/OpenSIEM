--
-- PostgreSQL database dump
--

\restrict 9xBZV7fgMjkoECOh4NHsxfmsWH38UmEZflT9AgfiyXaJZSM9vxCikwo9Vj30yki

-- Dumped from database version 18.6 (Ubuntu 18.6-0ubuntu0.26.04.1)
-- Dumped by pg_dump version 18.6 (Ubuntu 18.6-0ubuntu0.26.04.1)

-- Started on 2026-11-13 13:38:56 PKT

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- TOC entry 2 (class 3079 OID 24581)
-- Name: pg_trgm; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;


--
-- TOC entry 3922 (class 0 OID 0)
-- Dependencies: 2
-- Name: EXTENSION pg_trgm; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pg_trgm IS 'text similarity measurement and index searching based on trigrams';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- TOC entry 220 (class 1259 OID 24662)
-- Name: Log_Source; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public."Log_Source" (
    source_id integer NOT NULL,
    source_name character varying(255),
    source_path character varying(255)
);


ALTER TABLE public."Log_Source" OWNER TO postgres;

--
-- TOC entry 221 (class 1259 OID 24668)
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
-- TOC entry 3923 (class 0 OID 0)
-- Dependencies: 221
-- Name: Log_Source_source_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public."Log_Source_source_id_seq" OWNED BY public."Log_Source".source_id;


--
-- TOC entry 256 (class 1259 OID 40985)
-- Name: alert_notes; Type: TABLE; Schema: public; Owner: opensiem
--

CREATE TABLE public.alert_notes (
    id integer NOT NULL,
    alert_id integer NOT NULL,
    author_id integer NOT NULL,
    note text NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.alert_notes OWNER TO opensiem;

--
-- TOC entry 255 (class 1259 OID 40984)
-- Name: alert_notes_id_seq; Type: SEQUENCE; Schema: public; Owner: opensiem
--

CREATE SEQUENCE public.alert_notes_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.alert_notes_id_seq OWNER TO opensiem;

--
-- TOC entry 3924 (class 0 OID 0)
-- Dependencies: 255
-- Name: alert_notes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: opensiem
--

ALTER SEQUENCE public.alert_notes_id_seq OWNED BY public.alert_notes.id;


--
-- TOC entry 222 (class 1259 OID 24669)
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
-- TOC entry 223 (class 1259 OID 24676)
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
-- TOC entry 3925 (class 0 OID 0)
-- Dependencies: 223
-- Name: alert_occurrences_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.alert_occurrences_id_seq OWNED BY public.alert_occurrences.id;


--
-- TOC entry 224 (class 1259 OID 24677)
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
    fk_msg_id integer,
    status character varying(20) DEFAULT 'open'::character varying,
    assigned_to integer,
    assigned_at timestamp with time zone,
    acknowledged_by integer,
    escalated_at timestamp with time zone,
    resolved_at timestamp with time zone,
    first_ack_at timestamp with time zone,
    CONSTRAINT alerts_status_check CHECK (((status)::text = ANY ((ARRAY['open'::character varying, 'investigating'::character varying, 'resolved'::character varying, 'false_positive'::character varying])::text[])))
);


ALTER TABLE public.alerts OWNER TO postgres;

--
-- TOC entry 225 (class 1259 OID 24688)
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
-- TOC entry 3926 (class 0 OID 0)
-- Dependencies: 225
-- Name: alerts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.alerts_id_seq OWNED BY public.alerts.id;


--
-- TOC entry 226 (class 1259 OID 24689)
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
-- TOC entry 227 (class 1259 OID 24699)
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
-- TOC entry 3927 (class 0 OID 0)
-- Dependencies: 227
-- Name: archive_audit_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.archive_audit_log_id_seq OWNED BY public.archive_audit_log.id;


--
-- TOC entry 228 (class 1259 OID 24700)
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
-- TOC entry 229 (class 1259 OID 24723)
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
-- TOC entry 3928 (class 0 OID 0)
-- Dependencies: 229
-- Name: archive_manifest_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.archive_manifest_id_seq OWNED BY public.archive_manifest.id;


--
-- TOC entry 230 (class 1259 OID 24724)
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
-- TOC entry 231 (class 1259 OID 24747)
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
-- TOC entry 232 (class 1259 OID 24764)
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
-- TOC entry 3929 (class 0 OID 0)
-- Dependencies: 232
-- Name: archive_rehydration_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.archive_rehydration_id_seq OWNED BY public.archive_rehydration.id;


--
-- TOC entry 233 (class 1259 OID 24765)
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
-- TOC entry 234 (class 1259 OID 24776)
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
-- TOC entry 235 (class 1259 OID 24790)
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
-- TOC entry 3930 (class 0 OID 0)
-- Dependencies: 235
-- Name: archive_storage_config_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.archive_storage_config_id_seq OWNED BY public.archive_storage_config.id;


--
-- TOC entry 236 (class 1259 OID 24791)
-- Name: calendar; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.calendar (
    data_id integer NOT NULL,
    date date,
    "time" time without time zone
);


ALTER TABLE public.calendar OWNER TO postgres;

--
-- TOC entry 237 (class 1259 OID 24795)
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
-- TOC entry 3931 (class 0 OID 0)
-- Dependencies: 237
-- Name: calendar_data_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.calendar_data_id_seq OWNED BY public.calendar.data_id;


--
-- TOC entry 259 (class 1259 OID 65850)
-- Name: calendar_rehydration_seq; Type: SEQUENCE; Schema: public; Owner: opensiem
--

CREATE SEQUENCE public.calendar_rehydration_seq
    AS integer
    START WITH -1
    INCREMENT BY -1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.calendar_rehydration_seq OWNER TO opensiem;

--
-- TOC entry 238 (class 1259 OID 24796)
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
-- TOC entry 239 (class 1259 OID 24802)
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
-- TOC entry 3932 (class 0 OID 0)
-- Dependencies: 239
-- Name: device_device_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.device_device_id_seq OWNED BY public.device.device_id;


--
-- TOC entry 260 (class 1259 OID 65851)
-- Name: device_rehydration_seq; Type: SEQUENCE; Schema: public; Owner: opensiem
--

CREATE SEQUENCE public.device_rehydration_seq
    AS integer
    START WITH -1
    INCREMENT BY -1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.device_rehydration_seq OWNER TO opensiem;

--
-- TOC entry 240 (class 1259 OID 24803)
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
-- TOC entry 241 (class 1259 OID 24817)
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
-- TOC entry 3933 (class 0 OID 0)
-- Dependencies: 241
-- Name: login_user_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.login_user_id_seq OWNED BY public.login.user_id;


--
-- TOC entry 242 (class 1259 OID 24818)
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
-- TOC entry 243 (class 1259 OID 24828)
-- Name: message; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.message (
    message_id integer NOT NULL,
    message_source integer,
    date integer,
    message text,
    log_source integer,
    device_id integer,
    process_id integer,
    rehydration_job_id integer
);


ALTER TABLE public.message OWNER TO postgres;

--
-- TOC entry 244 (class 1259 OID 24834)
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
-- TOC entry 3934 (class 0 OID 0)
-- Dependencies: 244
-- Name: message_message_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.message_message_id_seq OWNED BY public.message.message_id;


--
-- TOC entry 245 (class 1259 OID 24835)
-- Name: process; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.process (
    process_id integer NOT NULL,
    process_name character varying(255),
    pid integer
);


ALTER TABLE public.process OWNER TO postgres;

--
-- TOC entry 246 (class 1259 OID 24839)
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
-- TOC entry 3935 (class 0 OID 0)
-- Dependencies: 246
-- Name: process_process_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.process_process_id_seq OWNED BY public.process.process_id;


--
-- TOC entry 262 (class 1259 OID 73733)
-- Name: saved_searches; Type: TABLE; Schema: public; Owner: opensiem
--

CREATE TABLE public.saved_searches (
    id integer NOT NULL,
    user_id integer NOT NULL,
    name character varying(80) NOT NULL,
    definition jsonb NOT NULL,
    shared boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.saved_searches OWNER TO opensiem;

--
-- TOC entry 261 (class 1259 OID 73732)
-- Name: saved_searches_id_seq; Type: SEQUENCE; Schema: public; Owner: opensiem
--

CREATE SEQUENCE public.saved_searches_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.saved_searches_id_seq OWNER TO opensiem;

--
-- TOC entry 3936 (class 0 OID 0)
-- Dependencies: 261
-- Name: saved_searches_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: opensiem
--

ALTER SEQUENCE public.saved_searches_id_seq OWNED BY public.saved_searches.id;


--
-- TOC entry 247 (class 1259 OID 24840)
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
-- TOC entry 248 (class 1259 OID 24847)
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
-- TOC entry 3937 (class 0 OID 0)
-- Dependencies: 248
-- Name: special_messages_msg_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.special_messages_msg_id_seq OWNED BY public.special_messages.msg_id;


--
-- TOC entry 258 (class 1259 OID 41010)
-- Name: ui_notifications; Type: TABLE; Schema: public; Owner: opensiem
--

CREATE TABLE public.ui_notifications (
    id integer NOT NULL,
    user_id integer NOT NULL,
    message text NOT NULL,
    alert_id integer,
    read_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.ui_notifications OWNER TO opensiem;

--
-- TOC entry 257 (class 1259 OID 41009)
-- Name: ui_notifications_id_seq; Type: SEQUENCE; Schema: public; Owner: opensiem
--

CREATE SEQUENCE public.ui_notifications_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.ui_notifications_id_seq OWNER TO opensiem;

--
-- TOC entry 3938 (class 0 OID 0)
-- Dependencies: 257
-- Name: ui_notifications_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: opensiem
--

ALTER SEQUENCE public.ui_notifications_id_seq OWNED BY public.ui_notifications.id;


--
-- TOC entry 249 (class 1259 OID 24848)
-- Name: use_cases; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.use_cases (
    case_id integer NOT NULL,
    case_name character varying NOT NULL,
    entity_field character varying(50) DEFAULT 'ip'::character varying,
    severity character varying(10) DEFAULT 'high'::character varying,
    time_window_seconds integer DEFAULT 300,
    cooldown_seconds integer DEFAULT 600,
    threshold_count integer,
    threshold_window_seconds integer,
    CONSTRAINT use_cases_severity_check CHECK (((severity)::text = ANY (ARRAY[('low'::character varying)::text, ('mid'::character varying)::text, ('high'::character varying)::text, ('critical'::character varying)::text])))
);


ALTER TABLE public.use_cases OWNER TO postgres;

--
-- TOC entry 250 (class 1259 OID 24860)
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
-- TOC entry 3939 (class 0 OID 0)
-- Dependencies: 250
-- Name: use_cases_case_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.use_cases_case_id_seq OWNED BY public.use_cases.case_id;


--
-- TOC entry 251 (class 1259 OID 24861)
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
-- TOC entry 252 (class 1259 OID 24871)
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
-- TOC entry 253 (class 1259 OID 24880)
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
-- TOC entry 3940 (class 0 OID 0)
-- Dependencies: 253
-- Name: watcher_health_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.watcher_health_id_seq OWNED BY public.watcher_health.id;


--
-- TOC entry 254 (class 1259 OID 24881)
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
-- TOC entry 3517 (class 2604 OID 24891)
-- Name: Log_Source source_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public."Log_Source" ALTER COLUMN source_id SET DEFAULT nextval('public."Log_Source_source_id_seq"'::regclass);


--
-- TOC entry 3607 (class 2604 OID 40988)
-- Name: alert_notes id; Type: DEFAULT; Schema: public; Owner: opensiem
--

ALTER TABLE ONLY public.alert_notes ALTER COLUMN id SET DEFAULT nextval('public.alert_notes_id_seq'::regclass);


--
-- TOC entry 3518 (class 2604 OID 24892)
-- Name: alert_occurrences id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alert_occurrences ALTER COLUMN id SET DEFAULT nextval('public.alert_occurrences_id_seq'::regclass);


--
-- TOC entry 3520 (class 2604 OID 24893)
-- Name: alerts id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alerts ALTER COLUMN id SET DEFAULT nextval('public.alerts_id_seq'::regclass);


--
-- TOC entry 3524 (class 2604 OID 24894)
-- Name: archive_audit_log id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_audit_log ALTER COLUMN id SET DEFAULT nextval('public.archive_audit_log_id_seq'::regclass);


--
-- TOC entry 3528 (class 2604 OID 24895)
-- Name: archive_manifest id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_manifest ALTER COLUMN id SET DEFAULT nextval('public.archive_manifest_id_seq'::regclass);


--
-- TOC entry 3556 (class 2604 OID 24896)
-- Name: archive_rehydration id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_rehydration ALTER COLUMN id SET DEFAULT nextval('public.archive_rehydration_id_seq'::regclass);


--
-- TOC entry 3567 (class 2604 OID 24897)
-- Name: archive_storage_config id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_storage_config ALTER COLUMN id SET DEFAULT nextval('public.archive_storage_config_id_seq'::regclass);


--
-- TOC entry 3572 (class 2604 OID 24898)
-- Name: calendar data_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.calendar ALTER COLUMN data_id SET DEFAULT nextval('public.calendar_data_id_seq'::regclass);


--
-- TOC entry 3573 (class 2604 OID 24899)
-- Name: device device_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.device ALTER COLUMN device_id SET DEFAULT nextval('public.device_device_id_seq'::regclass);


--
-- TOC entry 3574 (class 2604 OID 24900)
-- Name: login user_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.login ALTER COLUMN user_id SET DEFAULT nextval('public.login_user_id_seq'::regclass);


--
-- TOC entry 3583 (class 2604 OID 24901)
-- Name: message message_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message ALTER COLUMN message_id SET DEFAULT nextval('public.message_message_id_seq'::regclass);


--
-- TOC entry 3584 (class 2604 OID 24902)
-- Name: process process_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.process ALTER COLUMN process_id SET DEFAULT nextval('public.process_process_id_seq'::regclass);


--
-- TOC entry 3611 (class 2604 OID 73736)
-- Name: saved_searches id; Type: DEFAULT; Schema: public; Owner: opensiem
--

ALTER TABLE ONLY public.saved_searches ALTER COLUMN id SET DEFAULT nextval('public.saved_searches_id_seq'::regclass);


--
-- TOC entry 3585 (class 2604 OID 24903)
-- Name: special_messages msg_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.special_messages ALTER COLUMN msg_id SET DEFAULT nextval('public.special_messages_msg_id_seq'::regclass);


--
-- TOC entry 3609 (class 2604 OID 41013)
-- Name: ui_notifications id; Type: DEFAULT; Schema: public; Owner: opensiem
--

ALTER TABLE ONLY public.ui_notifications ALTER COLUMN id SET DEFAULT nextval('public.ui_notifications_id_seq'::regclass);


--
-- TOC entry 3587 (class 2604 OID 24904)
-- Name: use_cases case_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.use_cases ALTER COLUMN case_id SET DEFAULT nextval('public.use_cases_case_id_seq'::regclass);


--
-- TOC entry 3597 (class 2604 OID 24905)
-- Name: watcher_health id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.watcher_health ALTER COLUMN id SET DEFAULT nextval('public.watcher_health_id_seq'::regclass);


--
-- TOC entry 3874 (class 0 OID 24662)
-- Dependencies: 220
-- Data for Name: Log_Source; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public."Log_Source" (source_id, source_name, source_path) FROM stdin;
\.


--
-- TOC entry 3910 (class 0 OID 40985)
-- Dependencies: 256
-- Data for Name: alert_notes; Type: TABLE DATA; Schema: public; Owner: opensiem
--

COPY public.alert_notes (id, alert_id, author_id, note, created_at) FROM stdin;
\.


--
-- TOC entry 3876 (class 0 OID 24669)
-- Dependencies: 222
-- Data for Name: alert_occurrences; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.alert_occurrences (id, alert_id_fk, occurred_at, fk_msg_id, source_ip, details) FROM stdin;
\.


--
-- TOC entry 3878 (class 0 OID 24677)
-- Dependencies: 224
-- Data for Name: alerts; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.alerts (id, alert_id, alert_type, severity, is_active, count, source_ip, acknowledged_time, admin_note, fk_msg_id, status, assigned_to, assigned_at, acknowledged_by, escalated_at, resolved_at, first_ack_at) FROM stdin;
\.


--
-- TOC entry 3880 (class 0 OID 24689)
-- Dependencies: 226
-- Data for Name: archive_audit_log; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.archive_audit_log (id, occurred_at, action, performed_by, user_id, partition_date, table_name, manifest_id, detail, ip_address, success, error_msg) FROM stdin;
\.


--
-- TOC entry 3882 (class 0 OID 24700)
-- Dependencies: 228
-- Data for Name: archive_manifest; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.archive_manifest (id, partition_date, table_name, file_path, row_count, file_size_bytes, sha256_hash, compression, encrypted, state, frozen, frozen_by, frozen_reason, frozen_at, partial, rows_exported, rows_total, created_at, updated_at, verified_at, deleted_at, error_msg, backend_type, storage_config_id) FROM stdin;
\.


--
-- TOC entry 3884 (class 0 OID 24724)
-- Dependencies: 230
-- Data for Name: archive_policy; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.archive_policy (id, enabled, hot_retention_days, cold_retention_days, run_time, compression, encrypt_at_rest, verify_after_export, delete_after_verify, partial_export_behaviour, storage_alert_threshold_gb, archive_messages, archive_alerts, archive_alert_occurrences, alerts_retention_days, updated_at, updated_by) FROM stdin;
\.


--
-- TOC entry 3885 (class 0 OID 24747)
-- Dependencies: 231
-- Data for Name: archive_rehydration; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.archive_rehydration (id, date_from, date_to, tables, state, rows_imported, started_by, user_id, auto_release_at, created_at, completed_at, released_at, error_msg, pid, partitions_total, partitions_done) FROM stdin;
\.


--
-- TOC entry 3887 (class 0 OID 24765)
-- Dependencies: 233
-- Data for Name: archive_schema_registry; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.archive_schema_registry (key, first_seen, last_seen, occurrence_count, promoted, data_type, example_value, source_parsers) FROM stdin;
\.


--
-- TOC entry 3888 (class 0 OID 24776)
-- Dependencies: 234
-- Data for Name: archive_storage_config; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.archive_storage_config (id, name, backend_type, is_active, config_json, credentials_enc, last_tested_at, last_test_ok, last_test_msg, created_at, updated_at) FROM stdin;
\.


--
-- TOC entry 3890 (class 0 OID 24791)
-- Dependencies: 236
-- Data for Name: calendar; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.calendar (data_id, date, "time") FROM stdin;
\.


--
-- TOC entry 3892 (class 0 OID 24796)
-- Dependencies: 238
-- Data for Name: device; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.device (device_id, device_type, device_name, device_ip, device_port) FROM stdin;
\.


--
-- TOC entry 3894 (class 0 OID 24803)
-- Dependencies: 240
-- Data for Name: login; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.login (user_id, username, email, password_hash, role, is_active, is_verified, created_at, updated_at, last_login, failed_attempts, locked_until) FROM stdin;
11	admin	admin@opensiem.local	$2y$12$mh3DQeX4cIdZCPDoemLRPevaHBNtxhO2.bhtTAHmXtDCc2St60TjC	admin	t	t	2026-11-12 13:34:48.682161	\N	\N	0	\N
\.


--
-- TOC entry 3896 (class 0 OID 24818)
-- Dependencies: 242
-- Data for Name: malicious_artifacts; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.malicious_artifacts (artifacts, "interval", severity, added_at, source_url) FROM stdin;
\.


--
-- TOC entry 3897 (class 0 OID 24828)
-- Dependencies: 243
-- Data for Name: message; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.message (message_id, message_source, date, message, log_source, device_id, process_id, rehydration_job_id) FROM stdin;
\.


--
-- TOC entry 3899 (class 0 OID 24835)
-- Dependencies: 245
-- Data for Name: process; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.process (process_id, process_name, pid) FROM stdin;
\.


--
-- TOC entry 3916 (class 0 OID 73733)
-- Dependencies: 262
-- Data for Name: saved_searches; Type: TABLE DATA; Schema: public; Owner: opensiem
--

COPY public.saved_searches (id, user_id, name, definition, shared, created_at) FROM stdin;
\.


--
-- TOC entry 3901 (class 0 OID 24840)
-- Dependencies: 247
-- Data for Name: special_messages; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.special_messages (case_id_fk, msg_id, message, can_repeat, "order") FROM stdin;
\.


--
-- TOC entry 3912 (class 0 OID 41010)
-- Dependencies: 258
-- Data for Name: ui_notifications; Type: TABLE DATA; Schema: public; Owner: opensiem
--

COPY public.ui_notifications (id, user_id, message, alert_id, read_at, created_at) FROM stdin;
\.


--
-- TOC entry 3903 (class 0 OID 24848)
-- Dependencies: 249
-- Data for Name: use_cases; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.use_cases (case_id, case_name, entity_field, severity, time_window_seconds, cooldown_seconds, threshold_count, threshold_window_seconds) FROM stdin;
\.


--
-- TOC entry 3905 (class 0 OID 24861)
-- Dependencies: 251
-- Data for Name: user_permissions; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.user_permissions (user_id, can_create, can_read, can_update, can_delete, archive_role) FROM stdin;
\.


--
-- TOC entry 3906 (class 0 OID 24871)
-- Dependencies: 252
-- Data for Name: watcher_health; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.watcher_health (id, client_name, source_ip, last_heartbeat_at, last_message_at, offline_threshold_minutes, is_online, marked_offline_at, alert_id_fk, created_at, updated_at) FROM stdin;
\.


--
-- TOC entry 3908 (class 0 OID 24881)
-- Dependencies: 254
-- Data for Name: watcher_health_settings; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.watcher_health_settings (id, default_offline_threshold_minutes, check_interval_seconds, enabled, updated_at) FROM stdin;
\.


--
-- TOC entry 3941 (class 0 OID 0)
-- Dependencies: 221
-- Name: Log_Source_source_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public."Log_Source_source_id_seq"', 659917070, true);


--
-- TOC entry 3942 (class 0 OID 0)
-- Dependencies: 255
-- Name: alert_notes_id_seq; Type: SEQUENCE SET; Schema: public; Owner: opensiem
--

SELECT pg_catalog.setval('public.alert_notes_id_seq', 13, true);


--
-- TOC entry 3943 (class 0 OID 0)
-- Dependencies: 223
-- Name: alert_occurrences_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.alert_occurrences_id_seq', 61140, true);


--
-- TOC entry 3944 (class 0 OID 0)
-- Dependencies: 225
-- Name: alerts_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.alerts_id_seq', 55762, true);


--
-- TOC entry 3945 (class 0 OID 0)
-- Dependencies: 227
-- Name: archive_audit_log_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.archive_audit_log_id_seq', 159, true);


--
-- TOC entry 3946 (class 0 OID 0)
-- Dependencies: 229
-- Name: archive_manifest_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.archive_manifest_id_seq', 32, true);


--
-- TOC entry 3947 (class 0 OID 0)
-- Dependencies: 232
-- Name: archive_rehydration_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.archive_rehydration_id_seq', 12, true);


--
-- TOC entry 3948 (class 0 OID 0)
-- Dependencies: 235
-- Name: archive_storage_config_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.archive_storage_config_id_seq', 20, true);


--
-- TOC entry 3949 (class 0 OID 0)
-- Dependencies: 237
-- Name: calendar_data_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.calendar_data_id_seq', 659961789, true);


--
-- TOC entry 3950 (class 0 OID 0)
-- Dependencies: 259
-- Name: calendar_rehydration_seq; Type: SEQUENCE SET; Schema: public; Owner: opensiem
--

SELECT pg_catalog.setval('public.calendar_rehydration_seq', -1, false);


--
-- TOC entry 3951 (class 0 OID 0)
-- Dependencies: 239
-- Name: device_device_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.device_device_id_seq', 659916335, true);


--
-- TOC entry 3952 (class 0 OID 0)
-- Dependencies: 260
-- Name: device_rehydration_seq; Type: SEQUENCE SET; Schema: public; Owner: opensiem
--

SELECT pg_catalog.setval('public.device_rehydration_seq', -1, false);


--
-- TOC entry 3953 (class 0 OID 0)
-- Dependencies: 241
-- Name: login_user_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.login_user_id_seq', 12, true);


--
-- TOC entry 3954 (class 0 OID 0)
-- Dependencies: 244
-- Name: message_message_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.message_message_id_seq', 717947645, true);


--
-- TOC entry 3955 (class 0 OID 0)
-- Dependencies: 246
-- Name: process_process_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.process_process_id_seq', 659915886, true);


--
-- TOC entry 3956 (class 0 OID 0)
-- Dependencies: 261
-- Name: saved_searches_id_seq; Type: SEQUENCE SET; Schema: public; Owner: opensiem
--

SELECT pg_catalog.setval('public.saved_searches_id_seq', 1, false);


--
-- TOC entry 3957 (class 0 OID 0)
-- Dependencies: 248
-- Name: special_messages_msg_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.special_messages_msg_id_seq', 15, true);


--
-- TOC entry 3958 (class 0 OID 0)
-- Dependencies: 257
-- Name: ui_notifications_id_seq; Type: SEQUENCE SET; Schema: public; Owner: opensiem
--

SELECT pg_catalog.setval('public.ui_notifications_id_seq', 5, true);


--
-- TOC entry 3959 (class 0 OID 0)
-- Dependencies: 250
-- Name: use_cases_case_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.use_cases_case_id_seq', 6, true);


--
-- TOC entry 3960 (class 0 OID 0)
-- Dependencies: 253
-- Name: watcher_health_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.watcher_health_id_seq', 333676516, true);


--
-- TOC entry 3626 (class 2606 OID 24907)
-- Name: Log_Source Log_Source_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public."Log_Source"
    ADD CONSTRAINT "Log_Source_pkey" PRIMARY KEY (source_id);


--
-- TOC entry 3700 (class 2606 OID 40997)
-- Name: alert_notes alert_notes_pkey; Type: CONSTRAINT; Schema: public; Owner: opensiem
--

ALTER TABLE ONLY public.alert_notes
    ADD CONSTRAINT alert_notes_pkey PRIMARY KEY (id);


--
-- TOC entry 3629 (class 2606 OID 24909)
-- Name: alert_occurrences alert_occurrences_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alert_occurrences
    ADD CONSTRAINT alert_occurrences_pkey PRIMARY KEY (id);


--
-- TOC entry 3633 (class 2606 OID 24911)
-- Name: alerts alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_pkey PRIMARY KEY (id);


--
-- TOC entry 3641 (class 2606 OID 24913)
-- Name: archive_audit_log archive_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_audit_log
    ADD CONSTRAINT archive_audit_log_pkey PRIMARY KEY (id);


--
-- TOC entry 3645 (class 2606 OID 24915)
-- Name: archive_manifest archive_manifest_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_manifest
    ADD CONSTRAINT archive_manifest_pkey PRIMARY KEY (id);


--
-- TOC entry 3648 (class 2606 OID 24917)
-- Name: archive_policy archive_policy_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_policy
    ADD CONSTRAINT archive_policy_pkey PRIMARY KEY (id);


--
-- TOC entry 3650 (class 2606 OID 24919)
-- Name: archive_rehydration archive_rehydration_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_rehydration
    ADD CONSTRAINT archive_rehydration_pkey PRIMARY KEY (id);


--
-- TOC entry 3653 (class 2606 OID 24921)
-- Name: archive_schema_registry archive_schema_registry_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_schema_registry
    ADD CONSTRAINT archive_schema_registry_pkey PRIMARY KEY (key);


--
-- TOC entry 3656 (class 2606 OID 24923)
-- Name: archive_storage_config archive_storage_config_name_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_storage_config
    ADD CONSTRAINT archive_storage_config_name_key UNIQUE (name);


--
-- TOC entry 3658 (class 2606 OID 24925)
-- Name: archive_storage_config archive_storage_config_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_storage_config
    ADD CONSTRAINT archive_storage_config_pkey PRIMARY KEY (id);


--
-- TOC entry 3660 (class 2606 OID 24927)
-- Name: calendar calendar_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.calendar
    ADD CONSTRAINT calendar_pkey PRIMARY KEY (data_id);


--
-- TOC entry 3666 (class 2606 OID 24929)
-- Name: device device_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.device
    ADD CONSTRAINT device_pkey PRIMARY KEY (device_id);


--
-- TOC entry 3670 (class 2606 OID 24931)
-- Name: login login_email_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.login
    ADD CONSTRAINT login_email_key UNIQUE (email);


--
-- TOC entry 3672 (class 2606 OID 24933)
-- Name: login login_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.login
    ADD CONSTRAINT login_pkey PRIMARY KEY (user_id);


--
-- TOC entry 3674 (class 2606 OID 24935)
-- Name: login login_username_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.login
    ADD CONSTRAINT login_username_key UNIQUE (username);


--
-- TOC entry 3684 (class 2606 OID 24937)
-- Name: message message_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message
    ADD CONSTRAINT message_pkey PRIMARY KEY (message_id);


--
-- TOC entry 3686 (class 2606 OID 24939)
-- Name: process process_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.process
    ADD CONSTRAINT process_pkey PRIMARY KEY (process_id);


--
-- TOC entry 3706 (class 2606 OID 73748)
-- Name: saved_searches saved_searches_pkey; Type: CONSTRAINT; Schema: public; Owner: opensiem
--

ALTER TABLE ONLY public.saved_searches
    ADD CONSTRAINT saved_searches_pkey PRIMARY KEY (id);


--
-- TOC entry 3708 (class 2606 OID 73750)
-- Name: saved_searches saved_searches_user_id_name_key; Type: CONSTRAINT; Schema: public; Owner: opensiem
--

ALTER TABLE ONLY public.saved_searches
    ADD CONSTRAINT saved_searches_user_id_name_key UNIQUE (user_id, name);


--
-- TOC entry 3688 (class 2606 OID 24941)
-- Name: special_messages special_messages_pkey1; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.special_messages
    ADD CONSTRAINT special_messages_pkey1 PRIMARY KEY (msg_id);


--
-- TOC entry 3704 (class 2606 OID 41021)
-- Name: ui_notifications ui_notifications_pkey; Type: CONSTRAINT; Schema: public; Owner: opensiem
--

ALTER TABLE ONLY public.ui_notifications
    ADD CONSTRAINT ui_notifications_pkey PRIMARY KEY (id);


--
-- TOC entry 3676 (class 2606 OID 24943)
-- Name: malicious_artifacts unique_artifact; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.malicious_artifacts
    ADD CONSTRAINT unique_artifact UNIQUE (artifacts);


--
-- TOC entry 3690 (class 2606 OID 24945)
-- Name: use_cases use_cases_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.use_cases
    ADD CONSTRAINT use_cases_pkey PRIMARY KEY (case_id);


--
-- TOC entry 3692 (class 2606 OID 24947)
-- Name: user_permissions user_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_permissions
    ADD CONSTRAINT user_permissions_pkey PRIMARY KEY (user_id);


--
-- TOC entry 3695 (class 2606 OID 24949)
-- Name: watcher_health watcher_health_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.watcher_health
    ADD CONSTRAINT watcher_health_pkey PRIMARY KEY (id);


--
-- TOC entry 3698 (class 2606 OID 24951)
-- Name: watcher_health_settings watcher_health_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.watcher_health_settings
    ADD CONSTRAINT watcher_health_settings_pkey PRIMARY KEY (id);


--
-- TOC entry 3637 (class 1259 OID 24952)
-- Name: archive_audit_log_action; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX archive_audit_log_action ON public.archive_audit_log USING btree (action);


--
-- TOC entry 3638 (class 1259 OID 24953)
-- Name: archive_audit_log_occurred_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX archive_audit_log_occurred_at ON public.archive_audit_log USING btree (occurred_at DESC);


--
-- TOC entry 3639 (class 1259 OID 24954)
-- Name: archive_audit_log_partition_date; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX archive_audit_log_partition_date ON public.archive_audit_log USING btree (partition_date);


--
-- TOC entry 3642 (class 1259 OID 24955)
-- Name: archive_manifest_date; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX archive_manifest_date ON public.archive_manifest USING btree (partition_date DESC);


--
-- TOC entry 3643 (class 1259 OID 24956)
-- Name: archive_manifest_partition_table; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX archive_manifest_partition_table ON public.archive_manifest USING btree (partition_date, table_name);


--
-- TOC entry 3646 (class 1259 OID 24957)
-- Name: archive_manifest_state; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX archive_manifest_state ON public.archive_manifest USING btree (state);


--
-- TOC entry 3651 (class 1259 OID 24958)
-- Name: archive_rehydration_state; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX archive_rehydration_state ON public.archive_rehydration USING btree (state);


--
-- TOC entry 3654 (class 1259 OID 24959)
-- Name: archive_storage_config_active; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX archive_storage_config_active ON public.archive_storage_config USING btree (is_active) WHERE (is_active = true);


--
-- TOC entry 3701 (class 1259 OID 41008)
-- Name: idx_alert_notes_alert_id; Type: INDEX; Schema: public; Owner: opensiem
--

CREATE INDEX idx_alert_notes_alert_id ON public.alert_notes USING btree (alert_id);


--
-- TOC entry 3630 (class 1259 OID 24960)
-- Name: idx_alert_occurrences_alert_id_fk; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_alert_occurrences_alert_id_fk ON public.alert_occurrences USING btree (alert_id_fk);


--
-- TOC entry 3631 (class 1259 OID 24961)
-- Name: idx_alert_occurrences_fk_msg_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_alert_occurrences_fk_msg_id ON public.alert_occurrences USING btree (fk_msg_id);


--
-- TOC entry 3634 (class 1259 OID 40983)
-- Name: idx_alerts_assigned_to; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_alerts_assigned_to ON public.alerts USING btree (assigned_to);


--
-- TOC entry 3635 (class 1259 OID 24962)
-- Name: idx_alerts_fk_msg_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_alerts_fk_msg_id ON public.alerts USING btree (fk_msg_id);


--
-- TOC entry 3636 (class 1259 OID 40982)
-- Name: idx_alerts_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_alerts_status ON public.alerts USING btree (status);


--
-- TOC entry 3661 (class 1259 OID 24963)
-- Name: idx_calendar_data_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_calendar_data_id ON public.calendar USING btree (data_id);


--
-- TOC entry 3662 (class 1259 OID 24964)
-- Name: idx_calendar_data_time; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_calendar_data_time ON public.calendar USING btree (data_id, "time");


--
-- TOC entry 3663 (class 1259 OID 24965)
-- Name: idx_calendar_date; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_calendar_date ON public.calendar USING btree (date);


--
-- TOC entry 3664 (class 1259 OID 24966)
-- Name: idx_calendar_datetime_expr; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_calendar_datetime_expr ON public.calendar USING btree (((date + "time")));


--
-- TOC entry 3667 (class 1259 OID 24967)
-- Name: idx_device_device_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_device_device_id ON public.device USING btree (device_id);


--
-- TOC entry 3668 (class 1259 OID 73756)
-- Name: idx_device_ip_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_device_ip_id ON public.device USING btree (device_ip, device_id DESC);


--
-- TOC entry 3627 (class 1259 OID 24968)
-- Name: idx_log_source_source_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_log_source_source_id ON public."Log_Source" USING btree (source_id);


--
-- TOC entry 3677 (class 1259 OID 24969)
-- Name: idx_message_date; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_message_date ON public.message USING btree (date);


--
-- TOC entry 3678 (class 1259 OID 24970)
-- Name: idx_message_device_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_message_device_id ON public.message USING btree (device_id);


--
-- TOC entry 3679 (class 1259 OID 24971)
-- Name: idx_message_log_source; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_message_log_source ON public.message USING btree (log_source);


--
-- TOC entry 3680 (class 1259 OID 24972)
-- Name: idx_message_message_search; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_message_message_search ON public.message USING gin (to_tsvector('english'::regconfig, message));


--
-- TOC entry 3681 (class 1259 OID 24973)
-- Name: idx_message_message_trgm; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_message_message_trgm ON public.message USING gin (message public.gin_trgm_ops);


--
-- TOC entry 3682 (class 1259 OID 65852)
-- Name: idx_message_rehydration_job; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_message_rehydration_job ON public.message USING btree (rehydration_job_id) WHERE (rehydration_job_id IS NOT NULL);


--
-- TOC entry 3702 (class 1259 OID 41032)
-- Name: idx_ui_notifications_user_id; Type: INDEX; Schema: public; Owner: opensiem
--

CREATE INDEX idx_ui_notifications_user_id ON public.ui_notifications USING btree (user_id, read_at);


--
-- TOC entry 3693 (class 1259 OID 24974)
-- Name: watcher_health_is_online; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX watcher_health_is_online ON public.watcher_health USING btree (is_online);


--
-- TOC entry 3696 (class 1259 OID 24975)
-- Name: watcher_health_source_ip; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX watcher_health_source_ip ON public.watcher_health USING btree (source_ip);


--
-- TOC entry 3722 (class 2606 OID 40998)
-- Name: alert_notes alert_notes_alert_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: opensiem
--

ALTER TABLE ONLY public.alert_notes
    ADD CONSTRAINT alert_notes_alert_id_fkey FOREIGN KEY (alert_id) REFERENCES public.alerts(id) ON DELETE CASCADE;


--
-- TOC entry 3723 (class 2606 OID 41003)
-- Name: alert_notes alert_notes_author_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: opensiem
--

ALTER TABLE ONLY public.alert_notes
    ADD CONSTRAINT alert_notes_author_id_fkey FOREIGN KEY (author_id) REFERENCES public.login(user_id) ON DELETE CASCADE;


--
-- TOC entry 3709 (class 2606 OID 24976)
-- Name: alert_occurrences alert_occurrences_alert_id_fk_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alert_occurrences
    ADD CONSTRAINT alert_occurrences_alert_id_fk_fkey FOREIGN KEY (alert_id_fk) REFERENCES public.alerts(id) ON DELETE CASCADE;


--
-- TOC entry 3710 (class 2606 OID 24981)
-- Name: alert_occurrences alert_occurrences_fk_msg_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alert_occurrences
    ADD CONSTRAINT alert_occurrences_fk_msg_id_fkey FOREIGN KEY (fk_msg_id) REFERENCES public.message(message_id);


--
-- TOC entry 3711 (class 2606 OID 40977)
-- Name: alerts alerts_acknowledged_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_acknowledged_by_fkey FOREIGN KEY (acknowledged_by) REFERENCES public.login(user_id) ON DELETE SET NULL;


--
-- TOC entry 3712 (class 2606 OID 40972)
-- Name: alerts alerts_assigned_to_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_assigned_to_fkey FOREIGN KEY (assigned_to) REFERENCES public.login(user_id) ON DELETE SET NULL;


--
-- TOC entry 3714 (class 2606 OID 24986)
-- Name: archive_audit_log archive_audit_log_manifest_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_audit_log
    ADD CONSTRAINT archive_audit_log_manifest_id_fkey FOREIGN KEY (manifest_id) REFERENCES public.archive_manifest(id) ON DELETE SET NULL;


--
-- TOC entry 3720 (class 2606 OID 24991)
-- Name: special_messages caseid; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.special_messages
    ADD CONSTRAINT caseid FOREIGN KEY (case_id_fk) REFERENCES public.use_cases(case_id);


--
-- TOC entry 3713 (class 2606 OID 24996)
-- Name: alerts fk_message; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT fk_message FOREIGN KEY (fk_msg_id) REFERENCES public.message(message_id);


--
-- TOC entry 3715 (class 2606 OID 25001)
-- Name: message message_date_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message
    ADD CONSTRAINT message_date_fkey FOREIGN KEY (date) REFERENCES public.calendar(data_id);


--
-- TOC entry 3716 (class 2606 OID 25006)
-- Name: message message_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message
    ADD CONSTRAINT message_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.device(device_id);


--
-- TOC entry 3717 (class 2606 OID 25011)
-- Name: message message_log_source_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message
    ADD CONSTRAINT message_log_source_fkey FOREIGN KEY (log_source) REFERENCES public."Log_Source"(source_id);


--
-- TOC entry 3718 (class 2606 OID 25016)
-- Name: message message_message_source_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message
    ADD CONSTRAINT message_message_source_fkey FOREIGN KEY (message_source) REFERENCES public."Log_Source"(source_id);


--
-- TOC entry 3719 (class 2606 OID 25021)
-- Name: message message_process_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message
    ADD CONSTRAINT message_process_id_fkey FOREIGN KEY (process_id) REFERENCES public.process(process_id);


--
-- TOC entry 3726 (class 2606 OID 73751)
-- Name: saved_searches saved_searches_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: opensiem
--

ALTER TABLE ONLY public.saved_searches
    ADD CONSTRAINT saved_searches_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.login(user_id) ON DELETE CASCADE;


--
-- TOC entry 3724 (class 2606 OID 41027)
-- Name: ui_notifications ui_notifications_alert_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: opensiem
--

ALTER TABLE ONLY public.ui_notifications
    ADD CONSTRAINT ui_notifications_alert_id_fkey FOREIGN KEY (alert_id) REFERENCES public.alerts(id) ON DELETE SET NULL;


--
-- TOC entry 3725 (class 2606 OID 41022)
-- Name: ui_notifications ui_notifications_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: opensiem
--

ALTER TABLE ONLY public.ui_notifications
    ADD CONSTRAINT ui_notifications_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.login(user_id) ON DELETE CASCADE;


--
-- TOC entry 3721 (class 2606 OID 25026)
-- Name: user_permissions user_permissions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_permissions
    ADD CONSTRAINT user_permissions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.login(user_id) ON DELETE CASCADE;


-- Completed on 2026-11-13 13:38:56 PKT

--
-- PostgreSQL database dump complete
--

\unrestrict 9xBZV7fgMjkoECOh4NHsxfmsWH38UmEZflT9AgfiyXaJZSM9vxCikwo9Vj30yki

