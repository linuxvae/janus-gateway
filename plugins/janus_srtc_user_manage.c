
#include "janus_srtc.h"

void* janus_srtc_user_manage_create_plugin(janus_callbacks *callback, const char *config_path);
int janus_srtc_user_manage_destory_plugin(void *ctx_);

static srtc_handle_call_pt          srtc_handle_call_next;
static srtc_handle_accept_pt          srtc_handle_accept_next;
static srtc_handle_hangup_pt          srtc_handle_hangup_next;
static srtc_incoming_rtp_pt          srtc_incoming_rtp_next;
static srtc_incoming_rtcp_pt          srtc_incoming_rtcp_next;
static srtc_incoming_data_pt          srtc_incoming_data_next;
static srtc_handle_message_pt          srtc_handle_message_next;


extern gboolean signal_server;
extern janus_plugin janus_srtc_plugin ;

srtc_module_t srtc_user_manage_module = {
	0,
	janus_srtc_user_manage_create_plugin,
	janus_srtc_user_manage_destory_plugin,
	NULL
};

extern gboolean signal_server;

typedef struct {
	//存储相关模块的配置信息
}srtc_user_manage_ctx_t;

typedef struct janus_srtc_user_manage_session {
	janus_plugin_session *handle;
	gchar *username;
	struct janus_srtc_user_manage_session *peer;
	volatile gint destroyed;
	janus_refcount ref;
}janus_srtc_user_manage_session;



static int
	janus_srtc_user_manage_handle_call(janus_plugin_session *handle, json_t *message, janus_message_call_t *v)
{
	if(signal_server){
		json_t *relay = json_object_get(message, "relay");
		if(relay != NULL){
			return srtc_handle_call_next(handle, message, v);
		}

		json_t *username = json_object_get(message, "username");
		const gchar *username_text = json_string_value(username);
		//find relay signal server
		json_t *body = json_object_get(message, "body");
		json_t *calleename = json_object_get(body, "calleename");
		const gchar *calleename_text = json_string_value(calleename);
		//find calleename_text in db
		//找到一个合适的mediaserver
		//通过性能比较等 IP: find_media_server() 设置 当前正在通话 且设置使用的mediaserver IP
		//char *relay_ip = "47.75.158.180";
		//int relay_port = 8188;
		//char *media_ip = "47.75.213.83";
		//int media_port = 8188;
		char *media_ip= "47.75.158.180";
		int media_port= 8188;
		char *relay_ip= "47.75.213.83";
		int relay_port = 8188;

		relay = json_object();
		json_t *media = json_object();
		json_object_set_new(relay, "dst_port", json_integer(relay_port));
		json_object_set_new(relay, "dst_ip", json_string(relay_ip));
		json_object_set_new(media, "dst_port", json_integer(media_port));
		json_object_set_new(media, "dst_ip", json_string(media_ip));
		json_object_set_new(message, "relay", relay);
		json_object_set_new(message, "media", media);

		char *message_text = json_dumps(message, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
		JANUS_LOG(LOG_ERR, "root message %s\n", message_text);
		free(message_text);
	}

	return srtc_handle_call_next(handle, message, v);
}
static int
	janus_srtc_user_manage_handle_accept(janus_plugin_session *handle, json_t *message, janus_message_accept_t *v)
{
	if(signal_server){
		//find relay signal server
		json_t *body = json_object_get(message, "body");
		json_t *callername = json_object_get(body, "callername");
		const gchar *callername_text = json_string_value(callername);
		//find calleename_text in db
		//找到一个合适的mediaserver
		//IP: find_media_server_by_caller(callername_text)
		//char *media_ip = "47.75.213.83";
		//int media_port = 8188;
		char *media_ip = "47.75.158.180";
		int media_port = 8188;

		json_t *media = json_object();
		json_object_set_new(media, "dst_port", json_integer(media_port));
		json_object_set_new(media, "dst_ip", json_string(media_ip));
		json_object_set_new(message, "media", media);
	}

	return srtc_handle_accept_next(handle, message, v);
}

static int
	janus_srtc_user_manage_handle_hangup(janus_plugin_session *handle)
{
	//清除db的状态且清除mediaserver
	return srtc_handle_hangup_next(handle);
}

int janus_srtc_user_manage_destory_plugin(void *ctx_){
	srtc_user_manage_ctx_t*ctx =(srtc_user_manage_ctx_t*)ctx_;

	g_free(ctx);
	ctx = NULL;
}
int janus_srtc_user_manage_handle_register(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep){
	//1、判断appkey的合法性
	//2、存储username 和当前服务器的外网IP
	json_t *root = json_object_get(message, "srtc");
	const gchar *root_text = json_string_value(root);
	if(strcasecmp(root_text, "register")!= 0){
		return srtc_handle_message_next(handle, transaction, message, jsep);
	}
	json_t *username = json_object_get(message, "username");
	const gchar *username_text = json_string_value(username);
	char *public_ip = janus_get_public_ip();
	//存储

	return 0;
}

void* janus_srtc_user_manage_create_plugin(janus_callbacks *callback, const char *config_path){
	srtc_handle_call_next = srtc_handle_call;
	srtc_handle_call = janus_srtc_user_manage_handle_call;
	srtc_handle_accept_next = srtc_handle_accept;
	srtc_handle_accept = janus_srtc_user_manage_handle_accept;
	srtc_handle_hangup_next = srtc_handle_hangup;
	srtc_handle_hangup = janus_srtc_user_manage_handle_hangup;
	srtc_handle_message_next = srtc_handle_message;
	srtc_handle_message = janus_srtc_user_manage_handle_register;
	srtc_user_manage_ctx_t *ctx =(srtc_user_manage_ctx_t*)g_malloc(sizeof(srtc_user_manage_ctx_t));
	memset(ctx, 0,sizeof(srtc_user_manage_ctx_t));
	return ctx;
}




