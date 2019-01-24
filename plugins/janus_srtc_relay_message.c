


//进行消息转发：接受到relay信息，+ip和port，进行转发 使用libwebsocket作为client 可能会出现并发的瓶颈
#include "janus_srtc.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>

#include <libwebsockets.h>
#define JANUS_RELAY_MESSAGE_PACKAGE			"janus.transport.websockets"

static srtc_handle_call_pt          srtc_handle_call_next;
static srtc_handle_accept_pt          srtc_handle_accept_next;
static srtc_handle_hangup_pt          srtc_handle_hangup_next;
static srtc_handle_message_pt          srtc_handle_message_next;
static srtc_destroy_session_pt 			srtc_destroy_session_next;



extern gboolean signal_server;
extern janus_plugin janus_srtc_plugin ;

/* JSON serialization options */
static size_t json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;

/* WebSockets service thread */
static GThread *ws_relay_thread = NULL;



void* janus_srtc_relay_pre_create_plugin(janus_callbacks *callback, const char *config_path);
srtc_module_t srtc_rlay_msg_module = {
	0,
	janus_srtc_relay_pre_create_plugin,
	NULL,
	NULL
};


typedef struct {

	unsigned short ws_ping_pong_interval;
	unsigned int timeout_secs;
	const char *iface;
	int 	wsport ;
	const char *wss_iface;
	int 	wss_port ;
	const char *ssl_private_key_password;
	char *cert_pem_path;
	char *cert_key_path;
	gint destory_flag;
	struct lws_context *wsc;
	janus_callbacks *gateway;
}srtc_relay_message_ctx_t;

typedef struct {
	janus_plugin_session *handle;
	struct lws_client_connect_info i;
	struct lws *wsi;
	char  	*callee_name;
	char 	*caller_name;
	GAsyncQueue *messages;
	char *incoming;							/* Buffer containing the incoming message to process (in case there are fragments) */
	unsigned char *buffer;					/* Buffer containing the message to send */
	int buflen;								/* Length of the buffer (may be resized after re-allocations) */
	int bufpending;							/* Data an interrupted previous write couldn't send */
	int bufoffset;							/* Offset from where the interrupted previous write should resume */
	gint initialized;
	gint stopping;
	janus_refcount ref; //后续来管理ref

}srtc_relay_message_session_t;

static int janus_client_websockets_callback(
		struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user, void *in, size_t len){

			JANUS_LOG(LOG_VERB, "[%d] WebSocket message  accepted\n", reason);
		srtc_relay_message_session_t *relay_session = (srtc_relay_message_session_t*)lws_wsi_user(wsi);
		if(relay_session == NULL){
			JANUS_LOG(LOG_ERR, "relay_session lws_wsi_user failed!\n");
			return 0;
		}
		srtc_relay_message_ctx_t *relay_ctx = srtc_get_module_ctx(srtc_rlay_msg_module);
		if(relay_ctx == NULL){
			JANUS_LOG(LOG_ERR, "srtc_relay_message_ctx_t srtc_get_module_ctx failed!\n");
			return 0;
		}

		int error;
		switch(reason) {
			case LWS_CALLBACK_CLIENT_ESTABLISHED: {
  				lws_callback_on_writable(wsi);
				JANUS_LOG(LOG_VERB, "[%p] WebSocket connectted \n", wsi);
				break;
			}
			case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
				JANUS_LOG(LOG_VERB, "[%p] WebSocket connect ERROR \n", wsi);
				janus_srtc_relay_destroy_session(relay_session->handle, &error);
				if(signal_server){
					json_error_t error;
					json_t *root = json_loads("{\"srtc\":\"event\",\"eventtype\":\"hangup\"}", 0, &error);
					relay_ctx->gateway->push_event(relay_session->handle, &janus_srtc_plugin, NULL, root, NULL);
				}
				break;
			case LWS_CALLBACK_CLOSED:
				janus_srtc_relay_destroy_session(relay_session->handle, &error);
				if(signal_server){
					json_error_t error;
					json_t *root = json_loads("{\"srtc\":\"event\",\"eventtype\":\"hangup\"}", 0, &error);
					relay_ctx->gateway->push_event(relay_session->handle, &janus_srtc_plugin, NULL, root, NULL);
				}
				break;
			case LWS_CALLBACK_WSI_DESTROY: {
				janus_srtc_relay_destroy_session(relay_session->handle, &error);
				if(signal_server){
					json_error_t error;
					json_t *root = json_loads("{\"srtc\":\"event\",\"eventtype\":\"hangup\"}", 0, &error);
					relay_ctx->gateway->push_event(relay_session->handle, &janus_srtc_plugin, NULL, root, NULL);
				}
				break;
			}

			case LWS_CALLBACK_CLIENT_WRITEABLE: {
				if(relay_session == NULL || relay_session->wsi == NULL){
					JANUS_LOG(LOG_ERR, "[%p] Invalid WebSocket client instance...\n", wsi);
					return -1;
				}
				if(relay_session->buffer && relay_session->bufpending > 0 && relay_session->bufoffset > 0
						&& !g_atomic_int_get(&relay_session->stopping)) {
					JANUS_LOG(LOG_HUGE, "[%p] Completing pending WebSocket write (still need to write last %d bytes)...\n",
						 wsi, relay_session->bufpending);
					int sent = lws_write(wsi, relay_session->buffer + relay_session->bufoffset, relay_session->bufpending, LWS_WRITE_TEXT);
					JANUS_LOG(LOG_HUGE, "[%p]   -- Sent %d/%d bytes\n", wsi, sent, relay_session->bufpending);
					if(sent > -1 && sent < relay_session->bufpending) {
						/* We still couldn't send everything that was left, we'll try and complete this in the next round */
						relay_session->bufpending -= sent;
						relay_session->bufoffset += sent;
					} else {
						/* Clear the pending/partial write queue */
						relay_session->bufpending = 0;
						relay_session->bufoffset = 0;
					}
					/* Done for this round, check the next response/notification later */
					lws_callback_on_writable(wsi);
					return 0;
				}
				char *response = g_async_queue_try_pop(relay_session->messages);
				if(response && !g_atomic_int_get(&relay_session->stopping)) {
					/* Gotcha! */
					int buflen = LWS_SEND_BUFFER_PRE_PADDING + strlen(response) + LWS_SEND_BUFFER_POST_PADDING;
					if (buflen > relay_session->buflen) {
						/* We need a larger shared buffer */
						JANUS_LOG(LOG_HUGE, "[%p] Re-allocating to %d bytes (was %d, response is %zu bytes)\n", wsi, buflen, relay_session->buflen, strlen(response));
						relay_session->buflen = buflen;
						relay_session->buffer = g_realloc(relay_session->buffer, buflen);
					}
					memcpy(relay_session->buffer + LWS_SEND_BUFFER_PRE_PADDING, response, strlen(response));
					JANUS_LOG(LOG_HUGE, "[%p] Sending WebSocket message (%zu bytes)...\n", wsi, strlen(response));
					int sent = lws_write(wsi, relay_session->buffer + LWS_SEND_BUFFER_PRE_PADDING, strlen(response), LWS_WRITE_TEXT);
					JANUS_LOG(LOG_HUGE, "[%p]   -- Sent %d/%zu bytes\n", wsi, sent, strlen(response));
					if(sent > -1 && sent < (int)strlen(response)) {
						/* We couldn't send everything in a single write, we'll complete this in the next round */
						relay_session->bufpending = strlen(response) - sent;
						relay_session->bufoffset = LWS_SEND_BUFFER_PRE_PADDING + sent;
						JANUS_LOG(LOG_HUGE, "[%p]   -- Couldn't write all bytes (%d missing), setting offset %d\n",
							wsi, relay_session->bufpending, relay_session->bufoffset);
					}
					/* We can get rid of the message */
					free(response);
					/* Done for this round, check the next response/notification later */
					lws_callback_on_writable(wsi);
					return 0;

				}
				break;
			}
			case LWS_CALLBACK_CLIENT_RECEIVE: {
				JANUS_LOG(LOG_VERB, "[%p] WebSocket Got %zu bytes: \n", wsi, len);
				if(!signal_server){
					//if OK:
					janus_srtc_relay_destroy_session(relay_session->handle, &error);
					return 0;
				}

				/* Is this a new message, or part of a fragmented one? */
				const size_t remaining = lws_remaining_packet_payload(wsi);
				if(relay_session->incoming == NULL) {
					JANUS_LOG(LOG_HUGE, "[%p] First fragment: %zu bytes, %zu remaining\n", wsi, len, remaining);
					relay_session->incoming = g_malloc(len+1);
					memcpy(relay_session->incoming, in, len);
					relay_session->incoming[len] = '\0';
					JANUS_LOG(LOG_INFO, "%s\n", relay_session->incoming);
				} else {
					size_t offset = strlen(relay_session->incoming);
					JANUS_LOG(LOG_HUGE, "[%p] Appending fragment: offset %zu, %zu bytes, %zu remaining\n",  wsi, offset, len, remaining);
					relay_session->incoming = g_realloc(relay_session->incoming, offset+len+1);
					memcpy(relay_session->incoming+offset, in, len);
					relay_session->incoming[offset+len] = '\0';
					JANUS_LOG(LOG_HUGE, "%s\n", relay_session->incoming+offset);
				}
				if(remaining > 0 || !lws_is_final_fragment(wsi)) {
					/* Still waiting for some more fragments */
					JANUS_LOG(LOG_HUGE, "[%p] Waiting for more fragments\n", wsi);
					return 0;
				}
				JANUS_LOG(LOG_HUGE, "[%p] Done, parsing message: %zu bytes\n", wsi, strlen(relay_session->incoming));
				/* If we got here, the message is complete: parse the JSON payload */
				json_error_t js_error;
				json_t *root = json_loads(relay_session->incoming, 0, &js_error);
				g_free(relay_session->incoming);
				relay_session->incoming = NULL;
				/* Notify the core, passing both the object and, since it may be needed, the error */
				relay_ctx->gateway->push_event(relay_session->handle, &janus_srtc_plugin, NULL, root, NULL);
				break;
			}

		}

		return 0;
}

/* Protocol mappings */
static struct lws_protocols ws_protocols[] = {
	{ "janus-protocol", janus_client_websockets_callback, 0, 0 },
	{ NULL, NULL, 0 }
};


static srtc_relay_message_session_t* janus_srtc_relay_create_session(char *ipaddress, int port, int is_wss){
	int ret = -1;
	srtc_relay_message_ctx_t *relay_ctx = srtc_get_module_ctx(srtc_rlay_msg_module);
	if(relay_ctx == NULL){
		JANUS_LOG(LOG_ERR, "srtc_rlay_msg_module ctx not create!\n");
		return ret;
	}
	srtc_relay_message_session_t* session = (srtc_relay_message_session_t*)g_malloc(sizeof(srtc_relay_message_session_t));
	if(session == NULL){
		JANUS_LOG(LOG_ERR, "ctx malloc failed!\n");
		return ret;
	}
	//create libsocket
	memset(&session->i, 0, sizeof(session->i));
	session->i.port = port;
	session->i.path = "/";
	session->i.context = relay_ctx->wsc;
	session->i.ssl_connection = is_wss;
	session->i.host = ipaddress;
	session->i.address= ipaddress;
	session->i.protocol = ws_protocols[0].name;
	session->i.pwsi = &session->wsi;
	session->i.userdata = session;

	session->incoming = NULL;
	session->buffer = NULL;
	session->buflen = 0;
	session->bufpending = 0;
	session->bufoffset = 0;
	session->initialized = 0;
	session->stopping = 0;

	session->messages = g_async_queue_new();
	session->wsi = lws_client_connect_via_info(&session->i);

	if(session->wsi == NULL){
		JANUS_LOG(LOG_ERR, "ctx lws_client_connect_via_info failed!\n");
		goto ERROR;
	}
	return session;
ERROR:
	if(session){
		g_free(session);
		session = NULL;
	}
}

static janus_srtc_session_t* create_session_and_relay(janus_plugin_session *handle, char *transaction, json_t *root, json_t *relay_server){
	srtc_relay_message_session_t* session;

	char *server_text = json_dumps(relay_server, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
	JANUS_LOG(LOG_WARN, "root message %s\n", server_text);
	free(server_text);
	janus_srtc_session_t* srtc_session = (janus_srtc_session_t*)handle->plugin_handle;
	json_t *relay_server_ip = json_object_get(relay_server, "dst_ip");
	const gchar *relay_server_ip_text = json_string_value(relay_server_ip);
	json_t *relay_server_port = json_object_get(relay_server, "dst_port");
	int relay_server_port_text = json_integer_value(relay_server_port);

	session = janus_srtc_relay_create_session(relay_server_ip_text, relay_server_port_text, 0);
	if(session == NULL){
		JANUS_LOG(LOG_ERR, "ctx janus_srtc_relay_create_csession create failed!\n");
		return NULL;
	}
	srtc_session->mod_srtc_sessions[srtc_rlay_msg_module.srtc_module_index] = session;
	/* Convert to string and enqueue */
	//json_object_del(root, "relay");
	session->handle = handle;
	char *payload = json_dumps(root, json_format);
	JANUS_LOG(LOG_INFO, "#####relay###WebSockets send message %s\n", payload);
	g_async_queue_push(session->messages, payload);
	lws_callback_on_writable(session->wsi);
	return session;
}


static int
	janus_srtc_relay_handle_call(janus_plugin_session *handle, json_t *root, janus_message_call_t *v)
{
	srtc_relay_message_ctx_t *relay_ctx = srtc_get_module_ctx(srtc_rlay_msg_module);
	if(relay_ctx == NULL){
		JANUS_LOG(LOG_ERR, "srtc_rlay_msg_module ctx not create!\n");
		return srtc_handle_call_next(handle, root, v);
	}
	srtc_relay_message_session_t* session = NULL;
	json_t *message = json_object_get(root, "srtc");
	const gchar *message_text = json_string_value(message);
	if(handle->srtc_type == SERVER_B){
		json_t *relay_server = json_object_get(root, "relay");
		json_object_set_new(root, "eventtype", json_string(message_text));
		json_object_set_new(root, "srtc", json_string("event"));

		v->jsep = relay_ctx->gateway->plugin_handle_peer_sdp(handle, v->jsep, FALSE);
		json_object_set_new(root, "jsep", v->jsep);
		if(relay_server){
			session = create_session_and_relay(handle,v->transaction, root, relay_server);
		}
		handle->srtc_type == SERVER_B;
	}else if(handle->srtc_type == SERVER_A){//创建session and创建websocket	，查找数据库找到callee IP+port进行relay，callback 发送给handle中的session
		json_t *media_server = json_object_get(root, "media");
		if(media_server){
			session = create_session_and_relay(handle,v->transaction, root, media_server);
		}
	}
	session->callee_name = g_strdup(v->callee_name);
	session->caller_name = g_strdup(v->caller_name);
	return srtc_handle_call_next(handle, root, v);
}
static int
	janus_srtc_relay_handle_accept(janus_plugin_session *handle, json_t *root, janus_message_accept_t *v)
{
	if(handle->srtc_type == SERVER_C){//创建session and创建websocket  ，查找数据库通过数据库模块找到callee IP+port进行relay，callback 发送给handle中的session
		json_t *media_server = json_object_get(root, "media");
		if(signal_server){
			create_session_and_relay(handle,v->transaction, root, media_server);
		}
	}
	return srtc_handle_accept_next(handle, root, v);
}

static int
	janus_srtc_relay_handle_hangup(janus_plugin_session *handle, json_t *root, janus_message_hangup_t *v)
{
	srtc_relay_message_session_t *session = srtc_get_module_session(handle, srtc_rlay_msg_module);
	if(session == NULL){
		return srtc_handle_hangup_next(handle, root, v);
	}
	//stoping =1 删session
	if(signal_server){//A/C通过websicket 发送
		char *payload = json_dumps(root, json_format);
		g_async_queue_push(session->messages, payload);
		lws_callback_on_writable(session->wsi);
	}
	return srtc_handle_hangup_next(handle, root, v);
}

static char *janus_websockets_get_interface_name(const char *ip) {
	struct ifaddrs *addrs = NULL, *iap = NULL;
	if(getifaddrs(&addrs) == -1)
		return NULL;
	for(iap = addrs; iap != NULL; iap = iap->ifa_next) {
		if(iap->ifa_addr && (iap->ifa_flags & IFF_UP)) {
			if(iap->ifa_addr->sa_family == AF_INET) {
				struct sockaddr_in *sa = (struct sockaddr_in *)(iap->ifa_addr);
				char buffer[16];
				inet_ntop(iap->ifa_addr->sa_family, (void *)&(sa->sin_addr), buffer, sizeof(buffer));
				if(!strcmp(ip, buffer)) {
					char *iface = g_strdup(iap->ifa_name);
					freeifaddrs(addrs);
					return iface;
				}
			} else if(iap->ifa_addr->sa_family == AF_INET6) {
				struct sockaddr_in6 *sa = (struct sockaddr_in6 *)(iap->ifa_addr);
				char buffer[48];
				inet_ntop(iap->ifa_addr->sa_family, (void *)&(sa->sin6_addr), buffer, sizeof(buffer));
				if(!strcmp(ip, buffer)) {
					char *iface = g_strdup(iap->ifa_name);
					freeifaddrs(addrs);
					return iface;
				}
			}
		}
	}
	freeifaddrs(addrs);
	return NULL;
}

static int janus_srtc_relay_message_parse_config_file(srtc_relay_message_ctx_t *relay_ctx, const char *config_path){
	//解析配置文件进行赋值
	/* Read configuration */
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_RELAY_MESSAGE_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_RELAY_MESSAGE_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_RELAY_MESSAGE_PACKAGE);
		JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
		config = janus_config_parse(filename);
	}
	if(config != NULL) {
		janus_config_print(config);
		janus_config_category *config_general = janus_config_get_create(config, NULL, janus_config_type_category, "general");
		janus_config_category *config_certs = janus_config_get_create(config, NULL, janus_config_type_category, "certificates");

		/* Handle configuration */
		janus_config_item *item = janus_config_get(config, config_general, janus_config_type_item, "json");
		if(item && item->value) {
			/* Check how we need to format/serialize the JSON output */
			if(!strcasecmp(item->value, "indented")) {
				/* Default: indented, we use three spaces for that */
				json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;
			} else if(!strcasecmp(item->value, "plain")) {
				/* Not indented and no new lines, but still readable */
				json_format = JSON_INDENT(0) | JSON_PRESERVE_ORDER;
			} else if(!strcasecmp(item->value, "compact")) {
				/* Compact, so no spaces between separators */
				json_format = JSON_COMPACT | JSON_PRESERVE_ORDER;
			} else {
				JANUS_LOG(LOG_WARN, "Unsupported JSON format option '%s', using default (indented)\n", item->value);
				json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;
			}
		}
		/* Check if we need to enable the transport level ping/pong mechanism */
		int pingpong_trigger = 0, pingpong_timeout = 0;
		item = janus_config_get(config, config_general, janus_config_type_item, "pingpong_trigger");
		if(item && item->value) {
#if (LWS_LIBRARY_VERSION_MAJOR >= 2 && LWS_LIBRARY_VERSION_MINOR >= 1) || (LWS_LIBRARY_VERSION_MAJOR >= 3)
			pingpong_trigger = atoi(item->value);
			if(pingpong_trigger < 0) {
				JANUS_LOG(LOG_WARN, "Invalid value for pingpong_trigger (%d), ignoring...\n", pingpong_trigger);
				pingpong_trigger = 0;
			}
#else
			JANUS_LOG(LOG_WARN, "WebSockets ping/pong only supported in libwebsockets >= 2.1\n");
#endif
		}
		item = janus_config_get(config, config_general, janus_config_type_item, "pingpong_timeout");
		if(item && item->value) {
#if (LWS_LIBRARY_VERSION_MAJOR >= 2 && LWS_LIBRARY_VERSION_MINOR >= 1) || (LWS_LIBRARY_VERSION_MAJOR >= 3)
			pingpong_timeout = atoi(item->value);
			if(pingpong_timeout < 0) {
				JANUS_LOG(LOG_WARN, "Invalid value for pingpong_timeout (%d), ignoring...\n", pingpong_timeout);
				pingpong_timeout = 0;
			}
#else
			JANUS_LOG(LOG_WARN, "WebSockets ping/pong only supported in libwebsockets >= 2.1\n");
#endif
		}
		if((pingpong_trigger && !pingpong_timeout) || (!pingpong_trigger && pingpong_timeout)) {
			JANUS_LOG(LOG_WARN, "pingpong_trigger and pingpong_timeout not both set, ignoring...\n");
		}
#if (LWS_LIBRARY_VERSION_MAJOR >= 2 && LWS_LIBRARY_VERSION_MINOR >= 1) || (LWS_LIBRARY_VERSION_MAJOR >= 3)
		if(pingpong_trigger > 0 && pingpong_timeout > 0) {
			relay_ctx->ws_ping_pong_interval = pingpong_trigger;
			relay_ctx->timeout_secs = pingpong_timeout;
		}
#endif
		/* Setup the Janus API WebSockets server(s) */
		item = janus_config_get(config, config_general, janus_config_type_item, "ws");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "WebSockets server disabled\n");
		} else {
			int wsport = 8188;
			item = janus_config_get(config, config_general, janus_config_type_item, "ws_port");
			if(item && item->value)
				wsport = atoi(item->value);
			char *interface = NULL;
			item = janus_config_get(config, config_general, janus_config_type_item, "ws_interface");
			if(item && item->value)
				interface = (char *)item->value;
			char *ip = NULL;
			item = janus_config_get(config, config_general, janus_config_type_item, "ws_ip");
			if(item && item->value) {
				ip = (char *)item->value;
				char *iface = janus_websockets_get_interface_name(ip);
				if(iface == NULL) {
					JANUS_LOG(LOG_WARN, "No interface associated with %s? Falling back to no interface...\n", ip);
				}
				ip = iface;
			}

			relay_ctx->wsport = wsport;
			relay_ctx->iface = g_strdup(ip ? ip : interface);
			g_free(ip);
		}

		/* Setup the Janus API WebSockets server(s) */
		item = janus_config_get(config, config_general, janus_config_type_item, "wss");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "Secure WebSockets server disabled\n");
		} else {
			int wsport = 8989;
			item = janus_config_get(config, config_general, janus_config_type_item, "wss_port");
			if(item && item->value)
				wsport = atoi(item->value);
			char *interface = NULL;
			item = janus_config_get(config, config_general, janus_config_type_item, "wss_interface");
			if(item && item->value)
				interface = (char *)item->value;
			char *ip = NULL;
			item = janus_config_get(config, config_general, janus_config_type_item, "wss_ip");
			if(item && item->value) {
				ip = (char *)item->value;
				char *iface = janus_websockets_get_interface_name(ip);
				if(iface == NULL) {
					JANUS_LOG(LOG_WARN, "No interface associated with %s? Falling back to no interface...\n", ip);
				}
				ip = iface;
			}
			item = janus_config_get(config, config_certs, janus_config_type_item, "cert_pem");
			if(!item || !item->value) {
				JANUS_LOG(LOG_FATAL, "Missing certificate/key path\n");
			} else {
				char *server_pem = (char *)item->value;
				char *server_key = (char *)item->value;
				char *password = NULL;
				item = janus_config_get(config, config_certs, janus_config_type_item, "cert_key");
				if(item && item->value)
					server_key = (char *)item->value;
				item = janus_config_get(config, config_certs, janus_config_type_item, "cert_pwd");
				if(item && item->value)
					password = (char *)item->value;
				JANUS_LOG(LOG_VERB, "Using certificates:\n\t%s\n\t%s\n", server_pem, server_key);

				relay_ctx->ssl_private_key_password = g_strdup(password);
				relay_ctx->wss_port = wsport;
				relay_ctx->wss_iface = g_strdup(ip ? ip : interface);
				relay_ctx->cert_key_path = g_strdup(server_key);
				relay_ctx->cert_pem_path = g_strdup(server_pem);
			}
			g_free(ip);

		}
	}
	janus_config_destroy(config);
	config = NULL;
	return 0;
}

void *janus_relay_websockets_thread(void *data) {
	srtc_relay_message_ctx_t *relay_ctx = (srtc_relay_message_ctx_t *)data;

	struct lws_context *service = relay_ctx->wsc;
	if(service == NULL) {
		JANUS_LOG(LOG_ERR, "Invalid service\n");
		return NULL;
	}

	JANUS_LOG(LOG_INFO, "WebSockets thread started\n");

	while(!g_atomic_int_get(&relay_ctx->destory_flag)) {
		/* libwebsockets is single thread, we cycle through events here */
		lws_service(service, 50);
	}

	/* Get rid of the WebSockets server */
	lws_cancel_service(service);
	/* Done */
	JANUS_LOG(LOG_INFO, "WebSockets thread ended\n");
	return NULL;
}
int janus_srtc_relay_handle_relay(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep){
	srtc_relay_message_session_t *session = srtc_get_module_session(handle, srtc_rlay_msg_module);
	if(session == NULL){
		return srtc_handle_message_next(handle, transaction, message, jsep);
	}
	json_t *root = json_object_get(message, "srtc");
	const gchar *root_text = json_string_value(root);
	if(handle->srtc_type == SERVER_A || handle->srtc_type == SERVER_C){
		if(!strcasecmp(root_text, "event")){
			return srtc_handle_message_next(handle, transaction, message, jsep);
		}
	}
	if(handle->srtc_type == SERVER_A|| handle->srtc_type == SERVER_C){
		if(!strcasecmp(root_text, "trickle")){
			char *payload = json_dumps(message, json_format);
			JANUS_LOG(LOG_WARN, "relay_message %s\n", payload);
			g_async_queue_push(session->messages, payload);
			lws_callback_on_writable(session->wsi);
		}
	}
	//其他信息转发 需要设定条件

	//if(handle->srtc_type == SERVER_A||handle->srtc_type == SERVER_C){
	//	//处理trickle
	//	char *payload = json_dumps(message, json_format);
	//	JANUS_LOG(LOG_WARN, "relay_message %s\n", payload);
	//	g_async_queue_push(session->messages, payload);
	//	lws_callback_on_writable(session->wsi);
	//}
	return srtc_handle_message_next(handle, transaction, message, jsep);
}

void janus_srtc_relay_destroy_session(janus_plugin_session *handle, int *error){
	srtc_relay_message_ctx_t *relay_ctx = (srtc_relay_message_ctx_t*)g_malloc(sizeof(srtc_relay_message_ctx_t));
	if(relay_ctx == 0){
		if(relay_ctx == NULL){
			JANUS_LOG(LOG_ERR, "srtc_relay_message_ctx_t malloc failed!\n");
			return srtc_destroy_session_next(handle, error);
		}
	}
	srtc_relay_message_session_t *relay_session = srtc_get_module_session(handle, srtc_rlay_msg_module);
	if(relay_session == NULL){
		return srtc_destroy_session_next(handle, error);
	}

	/* Cleanup */
	JANUS_LOG(LOG_INFO, "[%p] Destroying WebSocket client\n", relay_session->wsi);
	relay_session->wsi = NULL;
	/* Remove messages queue too, if needed */
	if(relay_session->messages != NULL) {
		char *response = NULL;
		while((response = g_async_queue_try_pop(relay_session->messages)) != NULL) {
			g_free(response);
		}
		g_async_queue_unref(relay_session->messages);
	}
	/* ... and the shared buffers */
	g_free(relay_session->incoming);
	relay_session->incoming = NULL;
	g_free(relay_session->buffer);
	relay_session->buffer = NULL;
	relay_session->buflen = 0;
	relay_session->bufpending = 0;
	relay_session->bufoffset = 0;
	return srtc_destroy_session_next(handle, error);
}

void* janus_srtc_relay_pre_create_plugin(janus_callbacks *callback, const char *config_path){

	srtc_handle_accept_next = srtc_handle_accept;
	srtc_handle_accept = janus_srtc_relay_handle_accept;

	srtc_handle_hangup_next = srtc_handle_hangup;
	srtc_handle_hangup = janus_srtc_relay_handle_hangup;

	srtc_handle_call_next = srtc_handle_call;
	srtc_handle_call = janus_srtc_relay_handle_call;

	srtc_handle_message_next = srtc_handle_message;
	srtc_handle_message = janus_srtc_relay_handle_relay;
	srtc_destroy_session_next = srtc_destroy_session;
	srtc_destroy_session =janus_srtc_relay_destroy_session;

	srtc_relay_message_ctx_t *relay_ctx = (srtc_relay_message_ctx_t*)g_malloc(sizeof(srtc_relay_message_ctx_t));
	if(relay_ctx == 0){
		if(relay_ctx == NULL){
			JANUS_LOG(LOG_ERR, "srtc_relay_message_ctx_t  malloc failed!\n");
			return NULL;
		}
	}
	memset(relay_ctx, 0,sizeof(srtc_relay_message_ctx_t));
	janus_srtc_relay_message_parse_config_file(relay_ctx, config_path);

	//create libwebsocket client context
	struct lws_context_creation_info info;
    struct lws *wsi = NULL;

    memset(&info, 0, sizeof info);
    info.port = CONTEXT_PORT_NO_LISTEN;
   	//info.iface = NULL;
    info.protocols = ws_protocols;
    info.ssl_cert_filepath = relay_ctx->cert_pem_path;
    info.ssl_private_key_filepath = relay_ctx->cert_key_path;
	info.ssl_private_key_password =  relay_ctx->ssl_private_key_password;
    info.extensions = NULL;
    info.gid = -1;
    info.uid = -1;
    info.options = 0;

    relay_ctx->wsc = lws_create_context(&info);
	if(relay_ctx->wsc == NULL) {
		JANUS_LOG(LOG_ERR, "Error creating libwebsockets context...\n");
		goto ERROR;	/* No point in keeping the plugin loaded */
	}
	GError *error = NULL;
	g_atomic_int_set(&relay_ctx->destory_flag, 0);
	ws_relay_thread = g_thread_try_new("ws thread", &janus_relay_websockets_thread, relay_ctx, &error);
	if(!ws_relay_thread) {
		g_atomic_int_set(&relay_ctx->destory_flag, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the WebSockets thread...\n", error->code, error->message ? error->message : "??");
		goto ERROR;
	}
	relay_ctx->gateway = callback;
	return relay_ctx;
ERROR:
	if(relay_ctx){
		if(relay_ctx->cert_key_path) g_free(relay_ctx->cert_key_path);
		if(relay_ctx->cert_pem_path) g_free(relay_ctx->cert_pem_path);
		if(relay_ctx->iface) g_free(relay_ctx->iface);
		if(relay_ctx->wss_iface) g_free(relay_ctx->wss_iface);
		if(relay_ctx->ssl_private_key_password) g_free(relay_ctx->ssl_private_key_password);
		g_free(relay_ctx);
	}
	return NULL;

}







