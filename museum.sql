--
-- PostgreSQL database dump
--

\restrict VxJULGwf5NnqfPzgCSHxW1Q4nM8F45gxnAWJ0flf9FkmhtaHBbFgoceVHYhF69U

-- Dumped from database version 16.13 (Ubuntu 16.13-0ubuntu0.24.04.1)
-- Dumped by pg_dump version 16.13 (Ubuntu 16.13-0ubuntu0.24.04.1)

-- Started on 2026-04-02 23:08:53 PKT

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

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- TOC entry 215 (class 1259 OID 16389)
-- Name: Log_Source; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public."Log_Source" (
    source_id integer NOT NULL,
    source_name character varying(255),
    source_path character varying(255)
);


ALTER TABLE public."Log_Source" OWNER TO postgres;

--
-- TOC entry 216 (class 1259 OID 16394)
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
-- TOC entry 3583 (class 0 OID 0)
-- Dependencies: 216
-- Name: Log_Source_source_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public."Log_Source_source_id_seq" OWNED BY public."Log_Source".source_id;


--
-- TOC entry 234 (class 1259 OID 16545)
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
-- TOC entry 233 (class 1259 OID 16544)
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
-- TOC entry 3584 (class 0 OID 0)
-- Dependencies: 233
-- Name: alert_occurrences_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.alert_occurrences_id_seq OWNED BY public.alert_occurrences.id;


--
-- TOC entry 217 (class 1259 OID 16395)
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
-- TOC entry 218 (class 1259 OID 16402)
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
-- TOC entry 3585 (class 0 OID 0)
-- Dependencies: 218
-- Name: alerts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.alerts_id_seq OWNED BY public.alerts.id;


--
-- TOC entry 219 (class 1259 OID 16403)
-- Name: calendar; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.calendar (
    data_id integer NOT NULL,
    date date,
    "time" time without time zone
);


ALTER TABLE public.calendar OWNER TO postgres;

--
-- TOC entry 220 (class 1259 OID 16406)
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
-- TOC entry 3586 (class 0 OID 0)
-- Dependencies: 220
-- Name: calendar_data_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.calendar_data_id_seq OWNED BY public.calendar.data_id;


--
-- TOC entry 221 (class 1259 OID 16407)
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
-- TOC entry 222 (class 1259 OID 16412)
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
-- TOC entry 3587 (class 0 OID 0)
-- Dependencies: 222
-- Name: device_device_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.device_device_id_seq OWNED BY public.device.device_id;


--
-- TOC entry 223 (class 1259 OID 16413)
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
-- TOC entry 224 (class 1259 OID 16423)
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
-- TOC entry 3588 (class 0 OID 0)
-- Dependencies: 224
-- Name: login_user_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.login_user_id_seq OWNED BY public.login.user_id;


--
-- TOC entry 225 (class 1259 OID 16424)
-- Name: malicious_artifacts; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.malicious_artifacts (
    artifacts text NOT NULL,
    "interval" integer DEFAULT 0,
    severity character varying(10) DEFAULT 'mid'::character varying,
    added_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    source_url character varying(500),
    CONSTRAINT malicious_artifacts_severity_check CHECK (((severity)::text = ANY ((ARRAY['low'::character varying, 'mid'::character varying, 'high'::character varying, 'critical'::character varying])::text[])))
);


ALTER TABLE public.malicious_artifacts OWNER TO postgres;

--
-- TOC entry 226 (class 1259 OID 16433)
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
-- TOC entry 227 (class 1259 OID 16438)
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
-- TOC entry 3589 (class 0 OID 0)
-- Dependencies: 227
-- Name: message_message_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.message_message_id_seq OWNED BY public.message.message_id;


--
-- TOC entry 228 (class 1259 OID 16439)
-- Name: process; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.process (
    process_id integer NOT NULL,
    process_name character varying(255),
    pid integer
);


ALTER TABLE public.process OWNER TO postgres;

--
-- TOC entry 229 (class 1259 OID 16442)
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
-- TOC entry 3590 (class 0 OID 0)
-- Dependencies: 229
-- Name: process_process_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.process_process_id_seq OWNED BY public.process.process_id;


--
-- TOC entry 230 (class 1259 OID 16443)
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
-- TOC entry 236 (class 1259 OID 16841)
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
-- TOC entry 3591 (class 0 OID 0)
-- Dependencies: 236
-- Name: special_messages_msg_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.special_messages_msg_id_seq OWNED BY public.special_messages.msg_id;


--
-- TOC entry 231 (class 1259 OID 16450)
-- Name: use_cases; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.use_cases (
    case_id integer NOT NULL,
    case_name character varying NOT NULL,
    entity_field character varying(50) DEFAULT 'ip'::character varying,
    severity character varying(10) DEFAULT 'high'::character varying,
    CONSTRAINT use_cases_severity_check CHECK (((severity)::text = ANY ((ARRAY['low'::character varying, 'mid'::character varying, 'high'::character varying, 'critical'::character varying])::text[])))
);


ALTER TABLE public.use_cases OWNER TO postgres;

--
-- TOC entry 235 (class 1259 OID 16839)
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
-- TOC entry 3592 (class 0 OID 0)
-- Dependencies: 235
-- Name: use_cases_case_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.use_cases_case_id_seq OWNED BY public.use_cases.case_id;


--
-- TOC entry 232 (class 1259 OID 16456)
-- Name: user_permissions; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_permissions (
    user_id integer NOT NULL,
    can_create boolean DEFAULT false,
    can_read boolean DEFAULT true,
    can_update boolean DEFAULT false,
    can_delete boolean DEFAULT false
);


ALTER TABLE public.user_permissions OWNER TO postgres;

--
-- TOC entry 3336 (class 2604 OID 16463)
-- Name: Log_Source source_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public."Log_Source" ALTER COLUMN source_id SET DEFAULT nextval('public."Log_Source_source_id_seq"'::regclass);


--
-- TOC entry 3362 (class 2604 OID 16548)
-- Name: alert_occurrences id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alert_occurrences ALTER COLUMN id SET DEFAULT nextval('public.alert_occurrences_id_seq'::regclass);


--
-- TOC entry 3337 (class 2604 OID 16464)
-- Name: alerts id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alerts ALTER COLUMN id SET DEFAULT nextval('public.alerts_id_seq'::regclass);


--
-- TOC entry 3340 (class 2604 OID 16465)
-- Name: calendar data_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.calendar ALTER COLUMN data_id SET DEFAULT nextval('public.calendar_data_id_seq'::regclass);


--
-- TOC entry 3341 (class 2604 OID 16466)
-- Name: device device_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.device ALTER COLUMN device_id SET DEFAULT nextval('public.device_device_id_seq'::regclass);


--
-- TOC entry 3342 (class 2604 OID 16467)
-- Name: login user_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.login ALTER COLUMN user_id SET DEFAULT nextval('public.login_user_id_seq'::regclass);


--
-- TOC entry 3351 (class 2604 OID 16468)
-- Name: message message_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message ALTER COLUMN message_id SET DEFAULT nextval('public.message_message_id_seq'::regclass);


--
-- TOC entry 3352 (class 2604 OID 16469)
-- Name: process process_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.process ALTER COLUMN process_id SET DEFAULT nextval('public.process_process_id_seq'::regclass);


--
-- TOC entry 3353 (class 2604 OID 16842)
-- Name: special_messages msg_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.special_messages ALTER COLUMN msg_id SET DEFAULT nextval('public.special_messages_msg_id_seq'::regclass);


--
-- TOC entry 3355 (class 2604 OID 16840)
-- Name: use_cases case_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.use_cases ALTER COLUMN case_id SET DEFAULT nextval('public.use_cases_case_id_seq'::regclass);


--
-- TOC entry 3556 (class 0 OID 16389)
-- Dependencies: 215
-- Data for Name: Log_Source; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public."Log_Source" (source_id, source_name, source_path) FROM stdin;
\.


--
-- TOC entry 3575 (class 0 OID 16545)
-- Dependencies: 234
-- Data for Name: alert_occurrences; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.alert_occurrences (id, alert_id_fk, occurred_at, fk_msg_id, source_ip, details) FROM stdin;
\.


--
-- TOC entry 3558 (class 0 OID 16395)
-- Dependencies: 217
-- Data for Name: alerts; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.alerts (id, alert_id, alert_type, severity, is_active, count, source_ip, acknowledged_time, admin_note, fk_msg_id) FROM stdin;
\.


--
-- TOC entry 3560 (class 0 OID 16403)
-- Dependencies: 219
-- Data for Name: calendar; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.calendar (data_id, date, "time") FROM stdin;
\.


--
-- TOC entry 3562 (class 0 OID 16407)
-- Dependencies: 221
-- Data for Name: device; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.device (device_id, device_type, device_name, device_ip, device_port) FROM stdin;
\.


--
-- TOC entry 3564 (class 0 OID 16413)
-- Dependencies: 223
-- Data for Name: login; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.login (user_id, username, email, password_hash, role, is_active, is_verified, created_at, updated_at, last_login, failed_attempts, locked_until) FROM stdin;
2	admin	admin@admin.com	$2y$10$fJojaFOd.GT0hY4nOEC6JuJMJNQph8F/a3ZBUFt2wYmp7g4FAL51q	admin	t	t	2026-03-08 00:57:30.801045	\N	\N	0	\N
\.


--
-- TOC entry 3566 (class 0 OID 16424)
-- Dependencies: 225
-- Data for Name: malicious_artifacts; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.malicious_artifacts (artifacts, "interval", severity, added_at, source_url) FROM stdin;
\.


--
-- TOC entry 3567 (class 0 OID 16433)
-- Dependencies: 226
-- Data for Name: message; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.message (message_id, message_source, date, message, log_source, device_id, process_id) FROM stdin;
\.


--
-- TOC entry 3569 (class 0 OID 16439)
-- Dependencies: 228
-- Data for Name: process; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.process (process_id, process_name, pid) FROM stdin;
\.


--
-- TOC entry 3571 (class 0 OID 16443)
-- Dependencies: 230
-- Data for Name: special_messages; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.special_messages (case_id_fk, msg_id, message, can_repeat, "order") FROM stdin;
\.


--
-- TOC entry 3572 (class 0 OID 16450)
-- Dependencies: 231
-- Data for Name: use_cases; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.use_cases (case_id, case_name, entity_field, severity) FROM stdin;
\.


--
-- TOC entry 3573 (class 0 OID 16456)
-- Dependencies: 232
-- Data for Name: user_permissions; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.user_permissions (user_id, can_create, can_read, can_update, can_delete) FROM stdin;
2	t	t	t	t
\.


--
-- TOC entry 3593 (class 0 OID 0)
-- Dependencies: 216
-- Name: Log_Source_source_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public."Log_Source_source_id_seq"', 1241948, true);


--
-- TOC entry 3594 (class 0 OID 0)
-- Dependencies: 233
-- Name: alert_occurrences_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.alert_occurrences_id_seq', 59610, true);


--
-- TOC entry 3595 (class 0 OID 0)
-- Dependencies: 218
-- Name: alerts_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.alerts_id_seq', 54713, true);


--
-- TOC entry 3596 (class 0 OID 0)
-- Dependencies: 220
-- Name: calendar_data_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.calendar_data_id_seq', 1241951, true);


--
-- TOC entry 3597 (class 0 OID 0)
-- Dependencies: 222
-- Name: device_device_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.device_device_id_seq', 1241946, true);


--
-- TOC entry 3598 (class 0 OID 0)
-- Dependencies: 224
-- Name: login_user_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.login_user_id_seq', 5, true);


--
-- TOC entry 3599 (class 0 OID 0)
-- Dependencies: 227
-- Name: message_message_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.message_message_id_seq', 1241736, true);


--
-- TOC entry 3600 (class 0 OID 0)
-- Dependencies: 229
-- Name: process_process_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.process_process_id_seq', 1241736, true);


--
-- TOC entry 3601 (class 0 OID 0)
-- Dependencies: 236
-- Name: special_messages_msg_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.special_messages_msg_id_seq', 12, true);


--
-- TOC entry 3602 (class 0 OID 0)
-- Dependencies: 235
-- Name: use_cases_case_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.use_cases_case_id_seq', 5, true);


--
-- TOC entry 3367 (class 2606 OID 16471)
-- Name: Log_Source Log_Source_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public."Log_Source"
    ADD CONSTRAINT "Log_Source_pkey" PRIMARY KEY (source_id);


--
-- TOC entry 3401 (class 2606 OID 16553)
-- Name: alert_occurrences alert_occurrences_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alert_occurrences
    ADD CONSTRAINT alert_occurrences_pkey PRIMARY KEY (id);


--
-- TOC entry 3370 (class 2606 OID 16473)
-- Name: alerts alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_pkey PRIMARY KEY (id);


--
-- TOC entry 3372 (class 2606 OID 16475)
-- Name: calendar calendar_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.calendar
    ADD CONSTRAINT calendar_pkey PRIMARY KEY (data_id);


--
-- TOC entry 3376 (class 2606 OID 16477)
-- Name: device device_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.device
    ADD CONSTRAINT device_pkey PRIMARY KEY (device_id);


--
-- TOC entry 3379 (class 2606 OID 16479)
-- Name: login login_email_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.login
    ADD CONSTRAINT login_email_key UNIQUE (email);


--
-- TOC entry 3381 (class 2606 OID 16481)
-- Name: login login_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.login
    ADD CONSTRAINT login_pkey PRIMARY KEY (user_id);


--
-- TOC entry 3383 (class 2606 OID 16483)
-- Name: login login_username_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.login
    ADD CONSTRAINT login_username_key UNIQUE (username);


--
-- TOC entry 3391 (class 2606 OID 16485)
-- Name: message message_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message
    ADD CONSTRAINT message_pkey PRIMARY KEY (message_id);


--
-- TOC entry 3393 (class 2606 OID 16487)
-- Name: process process_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.process
    ADD CONSTRAINT process_pkey PRIMARY KEY (process_id);


--
-- TOC entry 3395 (class 2606 OID 16489)
-- Name: special_messages special_messages_pkey1; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.special_messages
    ADD CONSTRAINT special_messages_pkey1 PRIMARY KEY (msg_id);


--
-- TOC entry 3385 (class 2606 OID 16491)
-- Name: malicious_artifacts unique_artifact; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.malicious_artifacts
    ADD CONSTRAINT unique_artifact UNIQUE (artifacts);


--
-- TOC entry 3397 (class 2606 OID 16493)
-- Name: use_cases use_cases_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.use_cases
    ADD CONSTRAINT use_cases_pkey PRIMARY KEY (case_id);


--
-- TOC entry 3399 (class 2606 OID 16495)
-- Name: user_permissions user_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_permissions
    ADD CONSTRAINT user_permissions_pkey PRIMARY KEY (user_id);


--
-- TOC entry 3402 (class 1259 OID 16564)
-- Name: idx_alert_occurrences_alert_id_fk; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_alert_occurrences_alert_id_fk ON public.alert_occurrences USING btree (alert_id_fk);


--
-- TOC entry 3373 (class 1259 OID 16496)
-- Name: idx_calendar_data_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_calendar_data_id ON public.calendar USING btree (data_id);


--
-- TOC entry 3374 (class 1259 OID 16497)
-- Name: idx_calendar_data_time; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_calendar_data_time ON public.calendar USING btree (data_id, "time");


--
-- TOC entry 3377 (class 1259 OID 16498)
-- Name: idx_device_device_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_device_device_id ON public.device USING btree (device_id);


--
-- TOC entry 3368 (class 1259 OID 16499)
-- Name: idx_log_source_source_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_log_source_source_id ON public."Log_Source" USING btree (source_id);


--
-- TOC entry 3386 (class 1259 OID 16500)
-- Name: idx_message_date; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_message_date ON public.message USING btree (date);


--
-- TOC entry 3387 (class 1259 OID 16501)
-- Name: idx_message_device_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_message_device_id ON public.message USING btree (device_id);


--
-- TOC entry 3388 (class 1259 OID 16502)
-- Name: idx_message_log_source; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_message_log_source ON public.message USING btree (log_source);


--
-- TOC entry 3389 (class 1259 OID 16503)
-- Name: idx_message_message_search; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_message_message_search ON public.message USING gin (to_tsvector('english'::regconfig, message));


--
-- TOC entry 3411 (class 2606 OID 16554)
-- Name: alert_occurrences alert_occurrences_alert_id_fk_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alert_occurrences
    ADD CONSTRAINT alert_occurrences_alert_id_fk_fkey FOREIGN KEY (alert_id_fk) REFERENCES public.alerts(id) ON DELETE CASCADE;


--
-- TOC entry 3412 (class 2606 OID 16559)
-- Name: alert_occurrences alert_occurrences_fk_msg_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alert_occurrences
    ADD CONSTRAINT alert_occurrences_fk_msg_id_fkey FOREIGN KEY (fk_msg_id) REFERENCES public.message(message_id);


--
-- TOC entry 3409 (class 2606 OID 16504)
-- Name: special_messages caseid; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.special_messages
    ADD CONSTRAINT caseid FOREIGN KEY (case_id_fk) REFERENCES public.use_cases(case_id);


--
-- TOC entry 3403 (class 2606 OID 16509)
-- Name: alerts fk_message; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT fk_message FOREIGN KEY (fk_msg_id) REFERENCES public.message(message_id);


--
-- TOC entry 3404 (class 2606 OID 16514)
-- Name: message message_date_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message
    ADD CONSTRAINT message_date_fkey FOREIGN KEY (date) REFERENCES public.calendar(data_id);


--
-- TOC entry 3405 (class 2606 OID 16519)
-- Name: message message_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message
    ADD CONSTRAINT message_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.device(device_id);


--
-- TOC entry 3406 (class 2606 OID 16524)
-- Name: message message_log_source_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message
    ADD CONSTRAINT message_log_source_fkey FOREIGN KEY (log_source) REFERENCES public."Log_Source"(source_id);


--
-- TOC entry 3407 (class 2606 OID 16529)
-- Name: message message_message_source_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message
    ADD CONSTRAINT message_message_source_fkey FOREIGN KEY (message_source) REFERENCES public."Log_Source"(source_id);


--
-- TOC entry 3408 (class 2606 OID 16534)
-- Name: message message_process_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message
    ADD CONSTRAINT message_process_id_fkey FOREIGN KEY (process_id) REFERENCES public.process(process_id);


--
-- TOC entry 3410 (class 2606 OID 16539)
-- Name: user_permissions user_permissions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_permissions
    ADD CONSTRAINT user_permissions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.login(user_id) ON DELETE CASCADE;


-- Completed on 2026-04-02 23:08:53 PKT

--
-- PostgreSQL database dump complete
--

\unrestrict VxJULGwf5NnqfPzgCSHxW1Q4nM8F45gxnAWJ0flf9FkmhtaHBbFgoceVHYhF69U

