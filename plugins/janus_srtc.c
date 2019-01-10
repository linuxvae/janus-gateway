#include "janus_srtc.h"

/* Plugin information */
#define JANUS_SRTC_VERSION			6
#define JANUS_SRTC_VERSION_STRING	"0.0.6"
#define JANUS_SRTC_DESCRIPTION		"This is a simple video call plugin for Janus, allowing two WebRTC peers to call each other through a server."
#define JANUS_SRTC_NAME			"JANUS SRTC plugin"
#define JANUS_SRTC_AUTHOR			"Meetecho s.r.l."
#define JANUS_SRTC_PACKAGE			"janus.plugin.videocall"


srtc_handle_call_pt          srtc_handle_call;

srtc_handle_message_pt          srtc_handle_message;
srtc_create_session_pt       srtc_create_session;
srtc_incoming_rtp_pt    srtc_incoming_rtp;
srtc_incoming_rtcp_pt     srtc_incoming_rtcp;
srtc_hangup_media_pt    srtc_hangup_media;
srtc_destroy_session_pt          srtc_destroy_session;
srtc_init_pt							srtc_init;
srtc_destroy_pt						srtc_destroy;

static int srtc_module_index = -1;//可以作成一个结构体


int janus_srtc_pre_create_plugin(int module_index);
/* Plugin methods */
janus_plugin *create(void);
int janus_srtc_init_init(janus_callbacks *callback, const char *config_path);
void janus_srtc_destroy_init(void);
int janus_srtc_get_api_compatibility_init(void);
int janus_srtc_get_version_init();
const char *janus_srtc_get_version_string_init(void);
const char *janus_srtc_get_description_init(void);
const char *janus_srtc_get_name_init(void);
const char *janus_srtc_get_author_init(void);
const char *janus_srtc_get_package_init(void);
void janus_srtc_create_session_init(janus_plugin_session *handle, int *error);
struct janus_plugin_result *janus_srtc_handle_message_init(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
void janus_srtc_setup_media_init(janus_plugin_session *handle);
void janus_srtc_incoming_rtp_init(janus_plugin_session *handle, int video, char *buf, int len);
void janus_srtc_incoming_rtcp_init(janus_plugin_session *handle, int video, char *buf, int len);
void janus_srtc_incoming_data_init(janus_plugin_session *handle, char *buf, int len);
void janus_srtc_slow_link_init(janus_plugin_session *handle, int uplink, int video);
void janus_srtc_hangup_media_init(janus_plugin_session *handle);
void janus_srtc_destroy_session_init(janus_plugin_session *handle, int *error);
json_t *janus_srtc_query_session_init(janus_plugin_session *handle);

/* Plugin setup */
static janus_plugin janus_srtc_plugin =
	JANUS_PLUGIN_INIT (
		.init = janus_srtc_init_init,
		.destroy = janus_srtc_destroy_init,

		.get_api_compatibility = janus_srtc_get_api_compatibility_init,
		.get_version = janus_srtc_get_version_init,
		.get_version_string = janus_srtc_get_version_string_init,
		.get_description = janus_srtc_get_description_init,
		.get_name = janus_srtc_get_name_init,
		.get_author = janus_srtc_get_author_init,
		.get_package = janus_srtc_get_package_init,

		.create_session = janus_srtc_create_session_init,
		.handle_message = janus_srtc_handle_message_init,
		.setup_media = janus_srtc_setup_media_init,
		.incoming_rtp = janus_srtc_incoming_rtp_init,
		.incoming_rtcp = janus_srtc_incoming_rtcp_init,
		.incoming_data = janus_srtc_incoming_data_init,
		.slow_link = janus_srtc_slow_link_init,
		.hangup_media = janus_srtc_hangup_media_init,
		.destroy_session = janus_srtc_destroy_session_init,
		.query_session = janus_srtc_query_session_init,
	);

	
extern  srtc_module_t srtc_rlay_msg_module;
srtc_module_t srtc_modules[]={srtc_rlay_msg_module};//简单的方法加载各个模块
int janus_max_srtc_module = sizeof(srtc_modules)/sizeof(srtc_module_t);

janus_plugin *create(void){
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_SRTC_NAME);
	int i=0;
	for(;i<janus_max_srtc_module;i++){
		srtc_modules[i]->mod_ctx = srtc_modules[i]->srtc_pre_create_plugin_pt();
		srtc_modules[i]->srtc_module_index = i;
	}
	return &janus_srtc_plugin;
}
int janus_srtc_init_init(janus_callbacks *callback, const char *config_path){

	return 0;
}
void janus_srtc_destroy_init(void);
int janus_srtc_get_api_compatibility_init(void){
	return 0;
}
int janus_srtc_get_version_init(void){
	return 0;
}
const char *janus_srtc_get_version_string_init(void){
	return NULL;
}
const char *janus_srtc_get_description_init(void){
	return NULL;
}
const char *janus_srtc_get_name_init(void){
	return NULL;
}
const char *janus_srtc_get_author_init(void){
	return NULL;
}
const char *janus_srtc_get_package_init(void){
	return NULL;
}
void janus_srtc_create_session_init(janus_plugin_session *handle, int *error){

}
struct int
	janus_srtc_handle_call_init(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep)
{	
	static janus_message_call_t  v;
	//解析message 后生成V todo
	
	return srtc_handle_call(handle, &v);
}

struct janus_plugin_result *
	janus_srtc_handle_message_init(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep)
{
	json_t *message = json_object_get(root, "srtc");
	const gchar *message_text = json_string_value(message);
	if(!strcasecmp(message_text, "call")){
		janus_srtc_handle_call_init(handle, transaction, message, jsep);
	}//有待继续添加其他
	return NULL;
}
void janus_srtc_setup_media_init(janus_plugin_session *handle){

}
void janus_srtc_incoming_rtp_init(janus_plugin_session *handle, int video, char *buf, int len){

}
void janus_srtc_incoming_rtcp_init(janus_plugin_session *handle, int video, char *buf, int len){

}
void janus_srtc_incoming_data_init(janus_plugin_session *handle, char *buf, int len){

}
void janus_srtc_slow_link_init(janus_plugin_session *handle, int uplink, int video){

}
void janus_srtc_hangup_media_init(janus_plugin_session *handle){

}
void janus_srtc_destroy_session_init(janus_plugin_session *handle, int *error){
	return ;
}
json_t *janus_srtc_query_session_init(janus_plugin_session *handle){
	return NULL;
}

//***************

static void janus_srtc_session_free(const janus_refcount *session_ref){

}
static int janus_srtc_create_session(janus_plugin_session *handle, int *error){
	janus_srtc_session_t *session = g_malloc0(sizeof(janus_srtc_session_t));
	session->handle = handle;
	session->mod_srtc_ctx = g_malloc0(janus_max_srtc_module*sizeof(void*));
	handle->plugin_handle = session;

	janus_refcount_init(&session->ref, janus_srtc_session_free);
	return srtc_create_session(handle, error);
}
static int janus_srtc_destroy_session(janus_plugin_session *handle, int *error){
	return srtc_destroy_session(handle, error);
}

static struct int
	janus_srtc_handle_call(janus_plugin_session *handle, janus_message_call_t *v)
{
	return 0;
}

static struct janus_plugin_result *
	janus_srtc_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep)
{
	return srtc_handle_message(handle, transaction, message, jsep);
}
static int janus_srtc_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len){
		return srtc_incoming_rtp(handle, video, buf,len);

}
static int janus_srtc_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len){
	return srtc_incoming_rtcp(handle, video, buf,len);

}
static int janus_srtc_incoming_data(janus_plugin_session *handle, char *buf, int len){
	return 0;
}
static int janus_srtc_hangup_media(janus_plugin_session *handle){
	return srtc_hangup_media(handle);
}

int janus_srtc_pre_create_plugin(int module_index){
	srtc_handle_call = janus_srtc_handle_call;
	srtc_handle_message = janus_srtc_handle_message;
	srtc_create_session = janus_srtc_create_session;
	srtc_incoming_rtp = janus_srtc_incoming_rtp;
	srtc_incoming_rtcp = janus_srtc_incoming_rtcp;
	srtc_hangup_media = janus_srtc_hangup_media;
	srtc_destroy_session = janus_srtc_destroy_session;
	srtc_init = NULL;
	srtc_destroy = NULL;
	return 0;
}



