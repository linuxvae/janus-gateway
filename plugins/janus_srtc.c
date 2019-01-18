#include "janus_srtc.h"

/* Plugin information */
#define JANUS_SRTC_VERSION			6
#define JANUS_SRTC_VERSION_STRING	"0.0.6"
#define JANUS_SRTC_DESCRIPTION		"This is a simple video call plugin for Janus, allowing two WebRTC peers to call each other through a server."
#define JANUS_SRTC_NAME			"JANUS SRTC plugin"
#define JANUS_SRTC_AUTHOR			"Meetecho s.r.l."
#define JANUS_SRTC_PACKAGE			"janus.plugin.srtc"



srtc_handle_call_pt          srtc_handle_call;
srtc_handle_accept_pt          srtc_handle_accept;
srtc_handle_hangup_pt          srtc_handle_hangup;
srtc_handle_message_pt          srtc_handle_message;

srtc_create_session_pt       srtc_create_session;
srtc_incoming_rtp_pt    srtc_incoming_rtp;
srtc_incoming_rtcp_pt     srtc_incoming_rtcp;
srtc_incoming_data_pt srtc_incoming_data;
srtc_hangup_media_pt    srtc_hangup_media;
srtc_destroy_session_pt          srtc_destroy_session;
srtc_init_pt							srtc_init;
srtc_destroy_pt						srtc_destroy;


static volatile gint initialized = 0, stopping = 0;
static janus_callbacks *gateway = NULL;
static GThread *handler_thread;
static void *janus_srtc_handler(void *data);


typedef struct janus_srtc_message {
	janus_plugin_session *handle;
	char *transaction;
	json_t *message;
	json_t *jsep;
} janus_srtc_message;
static GAsyncQueue *messages = NULL;
static janus_srtc_message exit_message;


static void janus_srtc_session_destroy(janus_srtc_session_t *session) {
	if(session && g_atomic_int_compare_and_exchange(&session->destroyed, 0, 1))
		janus_refcount_decrease(&session->ref);
}

static void janus_srtc_session_free(const janus_refcount *session_ref) {
	janus_srtc_session_t *session = janus_refcount_containerof(session_ref, janus_srtc_session_t, ref);
	/* Remove the reference to the core plugin session */
	janus_refcount_decrease(&session->handle->ref);
	/* This session can be destroyed, free all the resources */
	//g_free(session->username);
	g_free(session);
}


/* Plugin methods */
janus_plugin *create(void);
int janus_srtc_init(janus_callbacks *callback, const char *config_path);
void janus_srtc_destroy(void);
int janus_srtc_get_api_compatibility(void);
int janus_srtc_get_version();
const char *janus_srtc_get_version_string(void);
const char *janus_srtc_get_description(void);
const char *janus_srtc_get_name(void);
const char *janus_srtc_get_author(void);
const char *janus_srtc_get_package(void);
void janus_srtc_create_session(janus_plugin_session *handle, int *error);
struct janus_plugin_result *janus_srtc_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
void janus_srtc_setup_media(janus_plugin_session *handle);
void janus_srtc_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_srtc_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_srtc_incoming_data(janus_plugin_session *handle, char *buf, int len);
void janus_srtc_slow_link(janus_plugin_session *handle, int uplink, int video);
void janus_srtc_hangup_media(janus_plugin_session *handle);
void janus_srtc_destroy_session(janus_plugin_session *handle, int *error);
json_t *janus_srtc_query_session(janus_plugin_session *handle);

/* Plugin setup */
janus_plugin janus_srtc_plugin =
	JANUS_PLUGIN_INIT (
		.init = janus_srtc_init,
		.destroy = janus_srtc_destroy,

		.get_api_compatibility = janus_srtc_get_api_compatibility,
		.get_version = janus_srtc_get_version,
		.get_version_string = janus_srtc_get_version_string,
		.get_description = janus_srtc_get_description,
		.get_name = janus_srtc_get_name,
		.get_author = janus_srtc_get_author,
		.get_package = janus_srtc_get_package,

		.create_session = janus_srtc_create_session,
		.handle_message = janus_srtc_handle_message,
		.setup_media = janus_srtc_setup_media,
		.incoming_rtp = janus_srtc_incoming_rtp,
		.incoming_rtcp = janus_srtc_incoming_rtcp,
		.incoming_data = janus_srtc_incoming_data,
		.slow_link = janus_srtc_slow_link,
		.hangup_media = janus_srtc_hangup_media,
		.destroy_session = janus_srtc_destroy_session,
		.query_session = janus_srtc_query_session,
	);


extern  srtc_module_t srtc_rlay_msg_module;
extern  srtc_module_t srtc_user_manage_module;
extern  srtc_module_t srtc_video_call_module;

srtc_module_t srtc_core_module;

srtc_module_t* srtc_modules[]={&srtc_core_module, &srtc_video_call_module, &srtc_rlay_msg_module, &srtc_user_manage_module};//简单的方法加载各个模块
int janus_max_srtc_module = sizeof(srtc_modules)/sizeof(srtc_module_t*);

janus_plugin *create(void){
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_SRTC_NAME);

	return &janus_srtc_plugin;
}



static void janus_srtc_message_free(janus_srtc_message *msg) {
	if(!msg || msg == &exit_message)
		return;

	if(msg->handle && msg->handle->plugin_handle) {
		janus_srtc_session_t *session = (janus_srtc_session_t *)msg->handle->plugin_handle;
		janus_refcount_decrease(&session->ref);
	}
	msg->handle = NULL;

	g_free(msg->transaction);
	msg->transaction = NULL;
	if(msg->message)
		json_decref(msg->message);
	msg->message = NULL;
	if(msg->jsep)
		json_decref(msg->jsep);
	msg->jsep = NULL;

	g_free(msg);
}

static void *janus_srtc_handler(void *data) {

	JANUS_LOG(LOG_VERB, "Joining janus_srtc_handler handler thread\n");
	janus_srtc_message *srtc_msg = NULL;
	int error_code = 0;
	char error_cause[512];
	json_t *root = NULL;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		srtc_msg = g_async_queue_pop(messages);
		if(srtc_msg == NULL)
			continue;
		if(srtc_msg == &exit_message)
			break;
		if(srtc_msg->handle == NULL) {
			janus_srtc_message_free(srtc_msg);
			continue;
		}
		janus_srtc_session_t *session = (janus_srtc_session_t *)srtc_msg->handle->plugin_handle;
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			janus_srtc_message_free(srtc_msg);
			continue;
		}
		if(g_atomic_int_get(&session->destroyed)) {
			janus_srtc_message_free(srtc_msg);
			continue;
		}


		error_code = 0;
		root = srtc_msg->message;
		json_t *jsep = srtc_msg->jsep;
		char *transaction = srtc_msg->transaction;
		janus_plugin_session *handle = srtc_msg->handle;
		if(srtc_msg->message == NULL) {
			JANUS_LOG(LOG_ERR, "No message??\n");
			error_code = JANUS_VIDEOCALL_ERROR_NO_MESSAGE;
			g_snprintf(error_cause, 512, "%s", "No message??");
			goto error;
		}
		if(!json_is_object(root)) {
			JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
			error_code = JANUS_VIDEOCALL_ERROR_INVALID_JSON;
			g_snprintf(error_cause, 512, "JSON error: not an object");
			goto error;
		}

		json_t *srtc = json_object_get(root, "srtc");
		const gchar *message_text = json_string_value(srtc);
		if(!strcasecmp(message_text, "call")){
			janus_srtc_handle_call_init(handle, transaction, root, jsep);
		}else if(!strcasecmp(message_text, "accept")){
			janus_srtc_handle_accept_init(handle, transaction, root, jsep);
		}else if(!strcasecmp(message_text, "hangup")){
			janus_srtc_handle_hangup_init(handle, transaction, root, jsep);

		}else{//register or tricle
			JANUS_LOG(LOG_ERR, "unkonw message %s...\n", message_text);
			srtc_handle_message(handle, transaction, root, jsep);
		}

		/* All the requests to this plugin are handled asynchronously */
error:
		continue;
	}
  return NULL;
}


int janus_srtc_init(janus_callbacks *callback, const char *config_path){
	if(g_atomic_int_get(&stopping)) {
		/* Still stopping from before */
		return -1;
	}

	if(callback == NULL || config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}
	messages = g_async_queue_new_full((GDestroyNotify) janus_srtc_message_free);
	gateway = callback;
	g_atomic_int_set(&initialized, 1);
	/* Launch the thread that will handle incoming messages */
	GError *error = NULL;
	handler_thread = g_thread_try_new("srtc handler", janus_srtc_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the VideoCall handler thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}

	int i=0;
	for(;i<janus_max_srtc_module;i++){
		srtc_modules[i]->mod_ctx = srtc_modules[i]->srtc_pre_create_plugin_pt(gateway, config_path);
		srtc_modules[i]->srtc_module_index = i;
	}


	return 0;
}
void janus_srtc_destroy(void){
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);

	g_async_queue_push(messages, &exit_message);
	if(handler_thread != NULL) {
		g_thread_join(handler_thread);
		handler_thread = NULL;
	}
	g_async_queue_unref(messages);
	messages = NULL;
	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_SRTC_NAME);


}
int janus_srtc_get_api_compatibility(void){
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_PLUGIN_API_VERSION;
}
int janus_srtc_get_version(void){
	return JANUS_SRTC_VERSION;
}
const char *janus_srtc_get_version_string(void){
	return JANUS_SRTC_VERSION_STRING;
}
const char *janus_srtc_get_description(void){
	return JANUS_SRTC_DESCRIPTION;
}
const char *janus_srtc_get_name(void){
	return JANUS_SRTC_NAME;
}
const char *janus_srtc_get_author(void){
	return JANUS_SRTC_AUTHOR;
}
const char *janus_srtc_get_package(void){
	return JANUS_SRTC_PACKAGE;
}
void janus_srtc_create_session(janus_plugin_session *handle, int *error){
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_srtc_session_t *session = g_malloc0(sizeof(janus_srtc_session_t));
	if(session == NULL){
		JANUS_LOG(LOG_VERB,"session is null malloc failed");
		exit(1);
	}
	session->mod_srtc_sessions = g_malloc(janus_max_srtc_module*sizeof(void*));
	if(session->mod_srtc_sessions == NULL){
		JANUS_LOG(LOG_VERB,"session is null malloc failed");
		exit(1);
	}
	session->handle = handle;
	handle->plugin_handle = session;
	janus_refcount_init(&session->ref, janus_srtc_session_free);
	return;


}
int	janus_srtc_handle_call_init(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep)
{
	static janus_message_call_t  v;
	//解析message 后生成V todo
	json_t *username = json_object_get(message, "username");
	v.caller_name = json_string_value(username);
	json_t *relay = json_object_get(message, "relay");
	json_t *body = json_object_get(message, "body");
	v.jsep = json_object_get(body, "jseep");
	json_t *callee_name = json_object_get(body, "calleename");
	v.callee_name = json_string_value(callee_name);
	if(relay != NULL){
		v.relay = 1;
	}
	return srtc_handle_call( handle, message, &v);
}
int janus_srtc_handle_accept_init(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep)
{
	static janus_message_accept_t  v;
	//解析message 后生成V todo

	return srtc_handle_accept( handle, message, &v);
}
int janus_srtc_handle_hangup_init(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep)
{
	static janus_message_hangup_t  v;
	//解析message 后生成V todo

	return srtc_handle_hangup( handle, message, &v);
}


struct janus_plugin_result *
	janus_srtc_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep)
{

	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
			return janus_plugin_result_new(JANUS_PLUGIN_ERROR, g_atomic_int_get(&stopping) ? "Shutting down" : "Plugin not initialized", NULL);
		janus_srtc_session_t *session = (janus_srtc_session_t *)handle->plugin_handle;
		if(!session)
			return janus_plugin_result_new(JANUS_PLUGIN_ERROR, "No session associated with this handle", NULL);

		janus_srtc_message *msg = g_malloc(sizeof(janus_srtc_message));
		/* Increase the reference counter for this session: we'll decrease it after we handle the message */
		janus_refcount_increase(&session->ref);

		msg->handle = handle;
		msg->transaction = transaction;
		msg->message = message;
		msg->jsep = jsep;
		g_async_queue_push(messages, msg);

		/* All the requests to this plugin are handled asynchronously */
		return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, NULL, NULL);

}
void janus_srtc_setup_media(janus_plugin_session *handle){

}
void janus_srtc_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len){

}
void janus_srtc_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len){

}
void janus_srtc_incoming_data(janus_plugin_session *handle, char *buf, int len){

}
void janus_srtc_slow_link(janus_plugin_session *handle, int uplink, int video){

}
void janus_srtc_hangup_media(janus_plugin_session *handle){

}
void janus_srtc_destroy_session(janus_plugin_session *handle, int *error){

	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_srtc_session_t *session = (janus_srtc_session_t*)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No srtc session associated with this handle...\n");
		*error = -2;
		return;
	}

//janus_videocall_hangup_media(handle);
	return;


	return ;
}
json_t *janus_srtc_query_session(janus_plugin_session *handle){
	return NULL;
}

//******core_module*********
void* janus_srtc_core_create_plugin(janus_callbacks *callback, const char *config_path);

srtc_module_t srtc_core_module = {
	0,
	janus_srtc_core_create_plugin,
	NULL,
	NULL
};
typedef struct {
	//存储相关模块的配置信息
}srtc_core_ctx_t;

static int
	janus_srtc_core_handle_call(janus_plugin_session *handle, json_t *message, janus_message_call_t *v)
{
	return 0;
}
static int
	janus_srtc_core_handle_accept(janus_plugin_session *handle, json_t *message, janus_message_accept_t *v)
{
	return 0;
}

static int
	janus_srtc_core_handle_hangup(janus_plugin_session *handle, json_t *message, janus_message_hangup_t *v)
{
	return 0;
}
static int janus_srtc_core_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len){
	return 0;
}
static int janus_srtc_core_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len){
	return 0;

}
int janus_srtc_core_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep){
	return 0;
}

void* janus_srtc_core_create_plugin(janus_callbacks *callback, const char *config_path){
	srtc_handle_call = janus_srtc_core_handle_call;
	srtc_handle_accept = janus_srtc_core_handle_accept;
	srtc_handle_hangup = janus_srtc_core_handle_hangup;
	srtc_incoming_rtp = janus_srtc_core_incoming_rtp;
	srtc_incoming_rtcp = janus_srtc_core_incoming_rtcp;
	srtc_handle_message = janus_srtc_core_message;
	srtc_core_ctx_t *ctx =(srtc_core_ctx_t*)g_malloc(sizeof(srtc_core_ctx_t));
	return ctx;
}



