--
-- PostgreSQL database dump
--

-- Dumped from database version 17.2
-- Dumped by pg_dump version 17.2

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

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: vuln; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.vuln (
    id integer NOT NULL,
    title text NOT NULL,
    description text,
    severity text,
    cve text,
    sensor text,
    endpoint text
);


ALTER TABLE public.vuln OWNER TO postgres;

--
-- Name: vuln_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.vuln_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.vuln_id_seq OWNER TO postgres;

--
-- Name: vuln_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.vuln_id_seq OWNED BY public.vuln.id;


--
-- Name: vuln id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vuln ALTER COLUMN id SET DEFAULT nextval('public.vuln_id_seq'::regclass);


--
-- Data for Name: vuln; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.vuln (id, title, description, severity, cve, sensor, endpoint) FROM stdin;
773	Information disclosure in config	Application config files are publicly accessible, causing information disclosure.	low	null	ToolA	/config
777	Session fixation in session	/session endpoint fails to renew session IDs. causing session fixation attacks.	high	null	ToolC	/session
782	CSRF vulnerability in cart checkout	Cart checkout page is susceptible to CSRF attacks through unprotected forms.	medium	null	ToolB	/cart
784	Weak encryption in api encrypt	Encryption mechanism in /api/encrypt is weak. allowing potential data exposure.	medium	null	ToolD	/api/encrypt
786	Session fixation discovered	Session fixation bug discovered in /session endpoint enables reusing another user's session token.	high	null	ToolB	/session
789	Missing HSTS policy	Lack of HSTS policy in the /secure endpoint leads to potential SSL stripping attacks.	low	null	ToolB	/secure
790	Reflected XSS on user profile	Reflected XSS discovered in profile endpoint, enabling malicious script execution.	medium	null	ToolC	/profile
791	Comments injection flaw	The /comments section is vulnerable to injection of arbitrary code via user content.	high	null	ToolC	/comments
792	SQL Injection vulnerability (login)	SQL injection detected at the login endpoint. Possible to inject SQL commands.	medium	null	ToolB	/login
793	Remote code execution found at /profile	The /profile endpoint can be exploited to run arbitrary commands on the server.	critical	null	ToolB	/profile
794	Profile authorization bypass	Profile authorization bypass could let normal users access privileged info.	medium	null	ToolB	/profile
796	SSTI vulnerability in EOL Apache	An end-of-life Apache version is prone to server-side template injection attacks.	medium	null	ToolC	/apache
788	Potential login SQL injection	Potential SQL injection vulnerability in the admin login flow, leading to database compromise.	critical	null	ToolD	/login
760	SQL Injection in login form	A critical SQL injection vulnerability found in the login form, allowing SQL queries injection.	high	CVE-2021-1111	ToolA	/login
762	XSS in user profile	A Cross-Site Scripting (XSS) issue in the user profile page allows script injection.	medium	null	ToolA	/profile
763	Config information disclosure	Leaking configuration data at /config can give attackers insights into the system.	medium	null	ToolC	/config
764	Cross-Site Scripting in profile page	Profile page is vulnerable to XSS if user-provided scripts are not sanitized.	high	null	ToolB	/profile
766	Comment injection in comments	Comment injection flaw at /comments endpoint allows attacker-supplied commands.	high	null	ToolB	/comments
769	Insecure file upload (upload endpoint)	Malicious file upload possible if the upload endpoint is not validating file types.	high	null	ToolA	/upload
770	File upload flaw in endpoint	A file upload flaw at /upload can be exploited to run arbitrary code on the server.	high	null	ToolC	/upload
772	Remote Code Execution at /config	Attackers can achieve code execution on the server via /config if not patched.	high	null	ToolD	/config
765	Obsolete Apache vulnerable to template injection	Obsolete version 2.2.x can be exploited via SSTI, leading to arbitrary code execution.	high	CVE-2025-1234	ToolD	/apache
767	Profile XSS vulnerability	The user profile section may allow XSS due to unsanitized input fields.	medium	CVE-2023-3333	ToolD	/profile
768	Server-Side Template Injection in old Apache	Apache 2.2.x is vulnerable to server-side template injection, potentially leading to RCE.	high	CVE-2025-1234	ToolA	/apache
771	Secret key exposure	Application accidentally exposes secret keys in the /secret route, allowing unauthorized access.	medium	CVE-2028-0001	ToolA	/secret
774	Cache poisoning in /assets	Malicious cache injection is possible in /assets, enabling attackers to serve rogue content.	high	CVE-2028-0002	ToolC	/assets
775	Subdomain takeover vulnerability	An unclaimed subdomain can be taken over, letting attackers host malicious content.	critical	CVE-2028-0003	ToolC	/subdomain
776	Public config leads to info disclosure	Sensitive data in config is exposed, leading to information disclosure issues.	high	CVE-2022-5555	ToolB	/config
778	Profile authorization bypass vulnerability	The profile endpoint fails to check user roles leading to authorization bypass.	medium	CVE-2025-0003	ToolC	/profile
779	Misconfigured config endpoint	A critical misconfiguration in /config reveals sensitive credentials and secrets.	critical	CVE-2022-5555	ToolD	/config
780	Arbitrary file upload vulnerability	Attackers can upload arbitrary files via the upload endpoint, leading to RCE.	critical	CVE-2021-4444	ToolB	/upload
781	Unauthenticated file upload vulnerability	The file upload endpoint accepts potentially harmful files without proper checks.	medium	CVE-2021-4444	ToolD	/upload
783	Directory Traversal in files	Attackers can manipulate file paths to access unauthorized directories in /files endpoint.	high	CVE-2024-0001	ToolC	/files
785	Arbitrary code execution in /profile	Unvalidated file input in /profile allows remote code execution.	high	CVE-2027-1001	ToolA	/profile
787	Comment injection vulnerability	Malicious users can inject code into comments leading to remote script execution.	high	CVE-2025-0002	ToolA	/comments
795	Session fixation vulnerability	Session fixation in /session allows attackers to hijack valid sessions after login.	high	CVE-2025-0004	ToolA	/session
797	Session fixation flaw	A critical session fixation flaw in /session can compromise user accounts.	critical	CVE-2025-0004	ToolD	/session
761	Suspected SQL Injection in adminstrator login	The admin login page may have an SQL injection flaw that allows malicious SQL queries.	high	CVE-2022-2222	ToolC	/login
800	RCE vulnerability in /config	A flaw in /config triggers remote code execution with crafted payloads.	high	CVE-2027-1002	ToolC	/config
798	CRLF injection in /headers	CRLF injection discovered in the /headers endpoint, allowing partial HTTP response splitting.	medium	null	ToolA	/headers
799	Apache 2.2.9 with SSTI flaw	Outdated Apache release allows server-side template injection if template engine is misconfigured.	critical	null	ToolB	/apache
801	CSRF in cart checkout	A CSRF vulnerability in the cart checkout flow can allow malicious form submissions.	medium	null	ToolA	/cart
\.


--
-- Name: vuln_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.vuln_id_seq', 801, true);


--
-- Name: vuln vuln_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vuln
    ADD CONSTRAINT vuln_pkey PRIMARY KEY (id);


--
-- PostgreSQL database dump complete
--

