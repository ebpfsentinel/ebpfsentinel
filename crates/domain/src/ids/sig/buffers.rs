//! The sticky buffers and the application fields a rule may name, with the
//! older spellings Suricata still reads.

/// A sticky buffer: the keyword that selects it, the application protocol
/// (or `packet`, `file`) that fills it, its older sticky names, the legacy
/// content modifier that moves a content into it, and the `pcre` flag that
/// selects it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferDef {
    pub name: &'static str,
    pub proto: &'static str,
    pub aliases: &'static [&'static str],
    pub modifier: Option<&'static str>,
    pub pcre_flag: Option<char>,
}

/// How an application field's argument is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldArg {
    /// The integer syntax.
    Int,
    /// The integer syntax or one or more names, optionally negated.
    Words,
    /// No argument.
    Flag,
    /// A value with a syntax of its own, checked by the parser where it has
    /// one.
    Raw,
}

/// An application field compared as a whole, outside any buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldDef {
    pub name: &'static str,
    pub proto: &'static str,
    pub arg: FieldArg,
}

#[rustfmt::skip]
pub const BUFFERS: &[BufferDef] = &[
    BufferDef { name: "file.data", proto: "file", aliases: &["file_data"], modifier: None, pcre_flag: None },
    BufferDef { name: "file.name", proto: "file", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "http.uri", proto: "http", aliases: &["http.uri.normalized"], modifier: Some("http_uri"), pcre_flag: Some('U') },
    BufferDef { name: "http.uri.raw", proto: "http", aliases: &[], modifier: Some("http_raw_uri"), pcre_flag: Some('I') },
    BufferDef { name: "http.method", proto: "http", aliases: &[], modifier: Some("http_method"), pcre_flag: Some('M') },
    BufferDef { name: "http.request_line", proto: "http", aliases: &["http_request_line"], modifier: None, pcre_flag: None },
    BufferDef { name: "http.request_body", proto: "http", aliases: &[], modifier: Some("http_client_body"), pcre_flag: Some('P') },
    BufferDef { name: "http.header", proto: "http", aliases: &[], modifier: Some("http_header"), pcre_flag: Some('H') },
    BufferDef { name: "http.header.raw", proto: "http", aliases: &[], modifier: Some("http_raw_header"), pcre_flag: Some('D') },
    BufferDef { name: "http.cookie", proto: "http", aliases: &[], modifier: Some("http_cookie"), pcre_flag: Some('C') },
    BufferDef { name: "http.user_agent", proto: "http", aliases: &[], modifier: Some("http_user_agent"), pcre_flag: Some('V') },
    BufferDef { name: "http.host", proto: "http", aliases: &[], modifier: Some("http_host"), pcre_flag: Some('W') },
    BufferDef { name: "http.host.raw", proto: "http", aliases: &[], modifier: Some("http_raw_host"), pcre_flag: None },
    BufferDef { name: "http.accept", proto: "http", aliases: &["http_accept"], modifier: None, pcre_flag: None },
    BufferDef { name: "http.accept_enc", proto: "http", aliases: &["http_accept_enc"], modifier: None, pcre_flag: None },
    BufferDef { name: "http.accept_lang", proto: "http", aliases: &["http_accept_lang"], modifier: None, pcre_flag: None },
    BufferDef { name: "http.referer", proto: "http", aliases: &["http_referer"], modifier: None, pcre_flag: None },
    BufferDef { name: "http.connection", proto: "http", aliases: &["http_connection"], modifier: None, pcre_flag: None },
    BufferDef { name: "http.content_type", proto: "http", aliases: &["http_content_type"], modifier: None, pcre_flag: None },
    BufferDef { name: "http.content_len", proto: "http", aliases: &["http_content_len"], modifier: None, pcre_flag: None },
    BufferDef { name: "http.start", proto: "http", aliases: &["http_start"], modifier: None, pcre_flag: None },
    BufferDef { name: "http.protocol", proto: "http", aliases: &["http_protocol"], modifier: None, pcre_flag: None },
    BufferDef { name: "http.header_names", proto: "http", aliases: &["http_header_names"], modifier: None, pcre_flag: None },
    BufferDef { name: "http.request_header", proto: "http", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "http.response_header", proto: "http", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "http.stat_code", proto: "http", aliases: &[], modifier: Some("http_stat_code"), pcre_flag: Some('S') },
    BufferDef { name: "http.stat_msg", proto: "http", aliases: &[], modifier: Some("http_stat_msg"), pcre_flag: Some('Y') },
    BufferDef { name: "http.response_line", proto: "http", aliases: &["http_response_line"], modifier: None, pcre_flag: None },
    BufferDef { name: "http.response_body", proto: "http", aliases: &[], modifier: Some("http_server_body"), pcre_flag: Some('Q') },
    BufferDef { name: "http.server", proto: "http", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "http.location", proto: "http", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "http2.header_name", proto: "http2", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "dns.query", proto: "dns", aliases: &["dns_query"], modifier: None, pcre_flag: None },
    BufferDef { name: "dns.queries.rrname", proto: "dns", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "dns.answers.rrname", proto: "dns", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "dns.authorities.rrname", proto: "dns", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "dns.additionals.rrname", proto: "dns", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "dns.response.rrname", proto: "dns", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "mdns.queries.rrname", proto: "mdns", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "mdns.answers.rrname", proto: "mdns", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "mdns.authorities.rrname", proto: "mdns", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "mdns.additionals.rrname", proto: "mdns", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "mdns.response.rrname", proto: "mdns", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "llmnr.queries.rrname", proto: "llmnr", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "llmnr.answers.rrname", proto: "llmnr", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "llmnr.authorities.rrname", proto: "llmnr", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "llmnr.additionals.rrname", proto: "llmnr", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "llmnr.response.rrname", proto: "llmnr", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "tls.sni", proto: "tls", aliases: &["tls_sni"], modifier: None, pcre_flag: None },
    BufferDef { name: "tls.cert_subject", proto: "tls", aliases: &["tls_cert_subject"], modifier: None, pcre_flag: None },
    BufferDef { name: "tls.cert_issuer", proto: "tls", aliases: &["tls_cert_issuer"], modifier: None, pcre_flag: None },
    BufferDef { name: "tls.cert_serial", proto: "tls", aliases: &["tls_cert_serial"], modifier: None, pcre_flag: None },
    BufferDef { name: "tls.cert_fingerprint", proto: "tls", aliases: &["tls_cert_fingerprint"], modifier: None, pcre_flag: None },
    BufferDef { name: "tls.certs", proto: "tls", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "tls.subjectaltname", proto: "tls", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "tls.alpn", proto: "tls", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "tls.random", proto: "tls", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "tls.random_time", proto: "tls", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "tls.random_bytes", proto: "tls", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "ja3.hash", proto: "tls", aliases: &["ja3_hash"], modifier: None, pcre_flag: None },
    BufferDef { name: "ja3.string", proto: "tls", aliases: &["ja3_string"], modifier: None, pcre_flag: None },
    BufferDef { name: "ja3s.hash", proto: "tls", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "ja3s.string", proto: "tls", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "ja4.hash", proto: "tls", aliases: &["ja4_hash"], modifier: None, pcre_flag: None },
    BufferDef { name: "ssh.proto", proto: "ssh", aliases: &["ssh_proto"], modifier: None, pcre_flag: None },
    BufferDef { name: "ssh.software", proto: "ssh", aliases: &["ssh_software"], modifier: None, pcre_flag: None },
    BufferDef { name: "ssh.hassh", proto: "ssh", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "ssh.hassh.string", proto: "ssh", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "ssh.hassh.server", proto: "ssh", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "ssh.hassh.server.string", proto: "ssh", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "ftp.command", proto: "ftp", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "ftp.command_data", proto: "ftp", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "ftp.completion_code", proto: "ftp", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "ftp.reply", proto: "ftp", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "smtp.helo", proto: "smtp", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "smtp.mail_from", proto: "smtp", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "smtp.rcpt_to", proto: "smtp", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "email.from", proto: "smtp", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "email.to", proto: "smtp", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "email.cc", proto: "smtp", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "email.subject", proto: "smtp", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "email.date", proto: "smtp", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "email.message_id", proto: "smtp", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "email.x_mailer", proto: "smtp", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "email.url", proto: "smtp", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "email.received", proto: "smtp", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "email.body_md5", proto: "smtp", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "smb.named_pipe", proto: "smb", aliases: &["smb_named_pipe"], modifier: None, pcre_flag: None },
    BufferDef { name: "smb.share", proto: "smb", aliases: &["smb_share"], modifier: None, pcre_flag: None },
    BufferDef { name: "smb.ntlmssp_user", proto: "smb", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "smb.ntlmssp_domain", proto: "smb", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "dcerpc.stub_data", proto: "smb", aliases: &["dce_stub_data"], modifier: None, pcre_flag: None },
    BufferDef { name: "krb5_cname", proto: "krb5", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "krb5_sname", proto: "krb5", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "snmp.community", proto: "snmp", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "snmp.usm", proto: "snmp", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "snmp.trap_oid", proto: "snmp", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "snmp.trap_address", proto: "snmp", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sip.method", proto: "sip", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sip.uri", proto: "sip", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sip.request_line", proto: "sip", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sip.stat_code", proto: "sip", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sip.stat_msg", proto: "sip", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sip.response_line", proto: "sip", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sip.protocol", proto: "sip", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sip.from", proto: "sip", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sip.to", proto: "sip", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sip.via", proto: "sip", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sip.user_agent", proto: "sip", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sip.content_type", proto: "sip", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sip.content_length", proto: "sip", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "quic.sni", proto: "quic", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "quic.ua", proto: "quic", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "quic.version", proto: "quic", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "quic.cyu.hash", proto: "quic", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "quic.cyu.string", proto: "quic", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "mqtt.connect.clientid", proto: "mqtt", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "mqtt.connect.username", proto: "mqtt", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "mqtt.connect.password", proto: "mqtt", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "mqtt.connect.willtopic", proto: "mqtt", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "mqtt.connect.willmessage", proto: "mqtt", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "mqtt.connect.protocol_string", proto: "mqtt", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "mqtt.publish.topic", proto: "mqtt", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "mqtt.publish.message", proto: "mqtt", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "mqtt.subscribe.topic", proto: "mqtt", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "mqtt.unsubscribe.topic", proto: "mqtt", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "ldap.request.dn", proto: "ldap", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "ldap.request.attribute_type", proto: "ldap", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "ldap.responses.dn", proto: "ldap", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "ldap.responses.message", proto: "ldap", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "ldap.responses.attribute_type", proto: "ldap", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "ldap.bind_request.sasl.mechanism", proto: "ldap", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "ldap.bind_request.sasl.credentials", proto: "ldap", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "ike.vendor", proto: "IKE", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "ike.key_exchange_payload", proto: "IKE", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "ike.nonce_payload", proto: "IKE", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "pgsql.query", proto: "PostgreSQL", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "rfb.name", proto: "RFB", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "websocket.payload", proto: "WebSocket", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "dnp3_data", proto: "DNP3", aliases: &["dnp3.data"], modifier: None, pcre_flag: None },
    BufferDef { name: "enip.product_name", proto: "ENIP", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "enip.service_name", proto: "ENIP", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "ntp.reference_id", proto: "NTP", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sdp.origin", proto: "SDP", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sdp.session_name", proto: "SDP", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sdp.session_info", proto: "SDP", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sdp.uri", proto: "SDP", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sdp.email", proto: "SDP", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sdp.phone_number", proto: "SDP", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sdp.connection_data", proto: "SDP", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sdp.bandwidth", proto: "SDP", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sdp.time", proto: "SDP", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sdp.repeat_time", proto: "SDP", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sdp.timezone", proto: "SDP", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sdp.encryption_key", proto: "SDP", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sdp.attribute", proto: "SDP", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sdp.media.media", proto: "SDP", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sdp.media.session_info", proto: "SDP", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sdp.media.connection_data", proto: "SDP", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sdp.media.encryption_key", proto: "SDP", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "ipv4.hdr", proto: "packet", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "ipv6.hdr", proto: "packet", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "tcp.hdr", proto: "packet", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "udp.hdr", proto: "packet", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "icmpv4.hdr", proto: "packet", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "icmpv6.hdr", proto: "packet", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "sctp.hdr", proto: "packet", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "igmp.hdr", proto: "packet", aliases: &[], modifier: None, pcre_flag: None },
    BufferDef { name: "ether.hdr", proto: "packet", aliases: &[], modifier: None, pcre_flag: None },
];

#[rustfmt::skip]
pub const FIELDS: &[FieldDef] = &[
    FieldDef { name: "dns.opcode", proto: "dns", arg: FieldArg::Int },
    FieldDef { name: "dns.rcode", proto: "dns", arg: FieldArg::Int },
    FieldDef { name: "dns.rrtype", proto: "dns", arg: FieldArg::Int },
    FieldDef { name: "tls.version", proto: "tls", arg: FieldArg::Raw },
    FieldDef { name: "ssl_version", proto: "tls", arg: FieldArg::Raw },
    FieldDef { name: "ssl_state", proto: "tls", arg: FieldArg::Raw },
    FieldDef { name: "tls.cert_chain_len", proto: "tls", arg: FieldArg::Int },
    FieldDef { name: "tls_cert_expired", proto: "tls", arg: FieldArg::Flag },
    FieldDef { name: "tls_cert_valid", proto: "tls", arg: FieldArg::Flag },
    FieldDef { name: "tls_cert_notbefore", proto: "tls", arg: FieldArg::Raw },
    FieldDef { name: "tls_cert_notafter", proto: "tls", arg: FieldArg::Raw },
    FieldDef { name: "tls.fingerprint", proto: "tls", arg: FieldArg::Raw },
    FieldDef { name: "tls.subject", proto: "tls", arg: FieldArg::Raw },
    FieldDef { name: "tls.issuerdn", proto: "tls", arg: FieldArg::Raw },
    FieldDef { name: "ssh.protoversion", proto: "ssh", arg: FieldArg::Raw },
    FieldDef { name: "ssh.softwareversion", proto: "ssh", arg: FieldArg::Raw },
    FieldDef { name: "http2.frametype", proto: "http2", arg: FieldArg::Words },
    FieldDef { name: "http2.errorcode", proto: "http2", arg: FieldArg::Words },
    FieldDef { name: "http2.priority", proto: "http2", arg: FieldArg::Int },
    FieldDef { name: "http2.window", proto: "http2", arg: FieldArg::Int },
    FieldDef { name: "http2.size_update", proto: "http2", arg: FieldArg::Int },
    FieldDef { name: "http2.settings", proto: "http2", arg: FieldArg::Raw },
    FieldDef { name: "dcerpc.iface", proto: "smb", arg: FieldArg::Raw },
    FieldDef { name: "dcerpc.opnum", proto: "smb", arg: FieldArg::Raw },
    FieldDef { name: "smb.version", proto: "smb", arg: FieldArg::Raw },
    FieldDef { name: "krb5_err_code", proto: "krb5", arg: FieldArg::Int },
    FieldDef { name: "krb5_msg_type", proto: "krb5", arg: FieldArg::Int },
    FieldDef { name: "krb5.ticket_encryption", proto: "krb5", arg: FieldArg::Raw },
    FieldDef { name: "krb5.weak_encryption", proto: "krb5", arg: FieldArg::Flag },
    FieldDef { name: "snmp.version", proto: "snmp", arg: FieldArg::Int },
    FieldDef { name: "snmp.pdu_type", proto: "snmp", arg: FieldArg::Int },
    FieldDef { name: "ftp.dynamic_port", proto: "ftp", arg: FieldArg::Int },
    FieldDef { name: "ftp.mode", proto: "ftp", arg: FieldArg::Words },
    FieldDef { name: "ftp.reply_received", proto: "ftp", arg: FieldArg::Words },
    FieldDef { name: "ftpdata_command", proto: "ftp", arg: FieldArg::Words },
    FieldDef { name: "mqtt.type", proto: "mqtt", arg: FieldArg::Words },
    FieldDef { name: "mqtt.flags", proto: "mqtt", arg: FieldArg::Raw },
    FieldDef { name: "mqtt.qos", proto: "mqtt", arg: FieldArg::Int },
    FieldDef { name: "mqtt.protocol_version", proto: "mqtt", arg: FieldArg::Int },
    FieldDef { name: "mqtt.reason_code", proto: "mqtt", arg: FieldArg::Int },
    FieldDef { name: "mqtt.connack.session_present", proto: "mqtt", arg: FieldArg::Words },
    FieldDef { name: "mqtt.connect.flags", proto: "mqtt", arg: FieldArg::Raw },
    FieldDef { name: "ldap.request.operation", proto: "ldap", arg: FieldArg::Words },
    FieldDef { name: "ldap.responses.operation", proto: "ldap", arg: FieldArg::Raw },
    FieldDef { name: "ldap.responses.count", proto: "ldap", arg: FieldArg::Int },
    FieldDef { name: "ldap.responses.result_code", proto: "ldap", arg: FieldArg::Raw },
    FieldDef { name: "ldap.bind_request.authentication", proto: "ldap", arg: FieldArg::Words },
    FieldDef { name: "ldap.bind_request.version", proto: "ldap", arg: FieldArg::Int },
    FieldDef { name: "modbus", proto: "Modbus", arg: FieldArg::Raw },
    FieldDef { name: "dnp3_func", proto: "DNP3", arg: FieldArg::Words },
    FieldDef { name: "dnp3.func", proto: "DNP3", arg: FieldArg::Words },
    FieldDef { name: "dnp3_ind", proto: "DNP3", arg: FieldArg::Raw },
    FieldDef { name: "dnp3.ind", proto: "DNP3", arg: FieldArg::Raw },
    FieldDef { name: "dnp3_obj", proto: "DNP3", arg: FieldArg::Raw },
    FieldDef { name: "dnp3.obj", proto: "DNP3", arg: FieldArg::Raw },
    FieldDef { name: "enip_command", proto: "ENIP", arg: FieldArg::Words },
    FieldDef { name: "cip_service", proto: "ENIP", arg: FieldArg::Raw },
    FieldDef { name: "enip.status", proto: "ENIP", arg: FieldArg::Int },
    FieldDef { name: "enip.vendor_id", proto: "ENIP", arg: FieldArg::Int },
    FieldDef { name: "enip.product_code", proto: "ENIP", arg: FieldArg::Int },
    FieldDef { name: "enip.device_type", proto: "ENIP", arg: FieldArg::Int },
    FieldDef { name: "nfs_procedure", proto: "NFS", arg: FieldArg::Int },
    FieldDef { name: "nfs.version", proto: "NFS", arg: FieldArg::Int },
    FieldDef { name: "rpc", proto: "RPC", arg: FieldArg::Raw },
    FieldDef { name: "ntp.mode", proto: "NTP", arg: FieldArg::Int },
    FieldDef { name: "ntp.stratum", proto: "NTP", arg: FieldArg::Int },
    FieldDef { name: "ntp.version", proto: "NTP", arg: FieldArg::Int },
    FieldDef { name: "rfb.secresult", proto: "RFB", arg: FieldArg::Words },
    FieldDef { name: "rfb.sectype", proto: "RFB", arg: FieldArg::Int },
    FieldDef { name: "ike.exchtype", proto: "IKE", arg: FieldArg::Int },
    FieldDef { name: "ike.chosen_sa_attribute", proto: "IKE", arg: FieldArg::Raw },
    FieldDef { name: "ike.key_exchange_payload_length", proto: "IKE", arg: FieldArg::Int },
    FieldDef { name: "ike.nonce_payload_length", proto: "IKE", arg: FieldArg::Int },
    FieldDef { name: "websocket.flags", proto: "WebSocket", arg: FieldArg::Raw },
    FieldDef { name: "websocket.mask", proto: "WebSocket", arg: FieldArg::Int },
    FieldDef { name: "websocket.opcode", proto: "WebSocket", arg: FieldArg::Words },
    FieldDef { name: "dhcp.leasetime", proto: "DHCP", arg: FieldArg::Int },
    FieldDef { name: "dhcp.rebinding_time", proto: "DHCP", arg: FieldArg::Int },
    FieldDef { name: "dhcp.renewal_time", proto: "DHCP", arg: FieldArg::Int },
    FieldDef { name: "sctp.chunk_type", proto: "packet", arg: FieldArg::Int },
    FieldDef { name: "sctp.vtag", proto: "packet", arg: FieldArg::Int },
    FieldDef { name: "sctp.chunk_cnt", proto: "packet", arg: FieldArg::Int },
    FieldDef { name: "frame", proto: "detect", arg: FieldArg::Raw },
];

/// The buffer a sticky keyword selects, by its name or an older one.
#[must_use]
pub fn sticky(keyword: &str) -> Option<&'static BufferDef> {
    BUFFERS
        .iter()
        .find(|b| b.name == keyword || b.aliases.contains(&keyword))
}

/// The buffer a legacy content modifier moves its content into.
#[must_use]
pub fn modifier(keyword: &str) -> Option<&'static BufferDef> {
    BUFFERS.iter().find(|b| b.modifier == Some(keyword))
}

/// The buffer a `pcre` flag selects.
#[must_use]
pub fn pcre_flag(flag: char) -> Option<&'static BufferDef> {
    BUFFERS.iter().find(|b| b.pcre_flag == Some(flag))
}

/// An application field by keyword.
#[must_use]
pub fn field(keyword: &str) -> Option<&'static FieldDef> {
    FIELDS.iter().find(|f| f.name == keyword)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_name_is_unique() {
        let mut seen = BTreeSet::new();
        for b in BUFFERS {
            for name in std::iter::once(&b.name)
                .chain(b.aliases)
                .chain(b.modifier.iter())
            {
                assert!(seen.insert(*name), "{name} twice");
            }
        }
        for f in FIELDS {
            assert!(seen.insert(f.name), "{} twice", f.name);
        }
    }

    #[test]
    fn legacy_spellings_reach_their_buffer() {
        assert_eq!(sticky("tls_sni").map(|b| b.name), Some("tls.sni"));
        assert_eq!(sticky("file_data").map(|b| b.name), Some("file.data"));
        assert_eq!(modifier("http_uri").map(|b| b.name), Some("http.uri"));
        assert_eq!(pcre_flag('U').map(|b| b.name), Some("http.uri"));
        assert_eq!(pcre_flag('Q').map(|b| b.name), Some("http.response_body"));
    }
}
