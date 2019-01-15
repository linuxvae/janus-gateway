


//点对点的实现
#include "janus_srtc.h"

void* janus_srtc_video_call_create_plugin(const char *config_path);

srtc_handle_call_pt          srtc_handle_call_next;
srtc_handle_accept_pt          srtc_handle_accept_next;
srtc_handle_hangup_pt          srtc_handle_hangup_next;
srtc_incoming_rtp_pt          srtc_incoming_rtp_next;
srtc_incoming_rtcp_pt          srtc_incoming_rtcp_next;
srtc_incoming_data_pt          srtc_incoming_data_next;



srtc_module_t srtc_video_call_module = {
	0,
	janus_srtc_video_call_create_plugin,
	janus_srtc_video_call_destory_plugin,
	NULL
};
typedef struct {
	//存储相关模块的配置信息
	GHashTable *sessions;
	janus_mutex sessions_mutex;
}srtc_video_call_ctx_t;

typedef struct janus_srtc_videocall_session {
	janus_plugin_session *handle;
	gchar *username;

	struct janus_srtc_videocall_session *peer;
	volatile gint incall;
	volatile gint hangingup;
	volatile gint destroyed;
	janus_refcount ref;

}janus_srtc_videocall_session;


static void janus_srtc_videocall_session_destroy(janus_srtc_videocall_session *session) {
	if(session && g_atomic_int_compare_and_exchange(&session->destroyed, 0, 1))
		janus_refcount_decrease(&session->ref);
}


static int
	janus_srtc_video_call_handle_call(janus_plugin_session *handle, json_t *message, janus_message_call_t *v)
{
	int error_code = 0;
	char error_cause[512];

	if(signal_server){
		return srtc_handle_call_next(handle, message, v);
	}
	janus_mutex_lock(&sessions_mutex);
	if(g_hash_table_lookup(sessions, v->caller_name) != NULL) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "Username '%s' already taken\n", v->caller_name);
		error_code = JANUS_VIDEOCALL_ERROR_USERNAME_TAKEN;
		g_snprintf(error_cause, 512, "Username '%s' already taken", v->caller_name);
		goto error;
	}
	janus_srtc_videocall_session *session = g_malloc0(sizeof(janus_srtc_videocall_session));
	session->handle = handle;
	janus_mutex_unlock(&sessions_mutex);
	session->username = g_strdup(v->caller_name);
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, (gpointer)session->username, session);
	janus_mutex_unlock(&sessions_mutex);

	srtc_set_module_session(handle, srtc_video_call_module, session);
	if(!g_atomic_int_compare_and_exchange(&session->incall, 0, 1)) {
		JANUS_LOG(LOG_ERR, "Already in a call (but no peer?)\n");
		error_code = JANUS_VIDEOCALL_ERROR_ALREADY_IN_CALL;
		g_snprintf(error_cause, 512, "Already in a call (but no peer)");
		/* Hangup the call attempt of the user */
		gateway->close_pc(session->handle);
		goto error;
	}
	
	return srtc_handle_call_next(handle, message, v);
error:	
	JANUS_LOG(LOG_VERB, "Leaving VideoCall handler thread error \n");
	return -1;
	
}
static int
	janus_srtc_video_call_handle_accept(janus_plugin_session *handle, json_t *message, janus_message_accept_t *v)
{	
	int error_code = 0;
	char error_cause[512];

	if(signal_server){
		return srtc_handle_accept_next(handle, message, v);
	}
	janus_mutex_lock(&sessions_mutex);
	if(g_hash_table_lookup(sessions, v->callee_name) != NULL) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "Username '%s' already taken\n", v->callee_name);
		error_code = JANUS_VIDEOCALL_ERROR_USERNAME_TAKEN;
		g_snprintf(error_cause, 512, "Username '%s' already taken", v->callee_name);
		goto error;
	}
	janus_srtc_videocall_session *session = g_malloc0(sizeof(janus_srtc_videocall_session));
	session->handle = handle;
	srtc_set_module_session(handle, srtc_video_call_module, session);
	janus_mutex_unlock(&sessions_mutex);
	session->username = g_strdup(v->callee_name);
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, (gpointer)session->username, session);
	janus_mutex_unlock(&sessions_mutex);
	if(!g_atomic_int_compare_and_exchange(&session->incall, 0, 1)) {
		JANUS_LOG(LOG_ERR, "Already in a call (but no peer?)\n");
		error_code = JANUS_VIDEOCALL_ERROR_ALREADY_IN_CALL;
		g_snprintf(error_cause, 512, "Already in a call (but no peer)");
		/* Hangup the call attempt of the user */
		gateway->close_pc(session->handle);
		goto error;
	}
	//查找peer
	janus_mutex_lock(&sessions_mutex);
	janus_srtc_videocall_session *peer = g_hash_table_lookup(sessions, v->caller_name);
	if(peer == NULL || g_atomic_int_get(&peer->destroyed)) {
		g_atomic_int_set(&session->incall, 0);
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "Username '%s' doesn't exist\n", v->caller_name);
		error_code = JANUS_VIDEOCALL_ERROR_NO_SUCH_USERNAME;
		g_snprintf(error_cause, 512, "Username '%s' doesn't exist", v->caller_name);
		/* Hangup the call attempt of the user */
		gateway->close_pc(session->handle);
		goto error;
	}
	session->peer = peer;
	peer->peer = session;
	/* If the call attempt proceeds we keep the references */
	janus_refcount_increase(&session->ref);
	janus_refcount_increase(&peer->ref);
	g_atomic_int_set(&peer->incall, 1);

	//重组message 形成accept 的answer todo
	int ret = gateway->push_event(peer->handle, &janus_srtc_plugin, NULL, message, v->jsep);

	janus_refcount_decrease(&peer->ref);
	
}

static int
	janus_srtc_video_call_handle_hangup(janus_plugin_session *handle, json_t *message, janus_message_hangup_t *v)
{
	if(signal_server){
		return srtc_handle_call_next(handle, message, v);
	}
	const char *hangup_text = v->reason;
	janus_srtc_videocall_session *session = srtc_get_module_session(handle, srtc_video_call_module);
	janus_srtc_videocall_session *peer = session->peer;
	if(peer == NULL) {
		JANUS_LOG(LOG_WARN, "No call to hangup\n");
	} else {
		JANUS_LOG(LOG_VERB, "%s is hanging up the call with %s (%s)\n", session->username, peer->username, hangup_text);
	}

	/* Check if we still need to remove any reference */
	if(peer && g_atomic_int_compare_and_exchange(&peer->incall, 1, 0)) {
		janus_refcount_decrease(&session->ref);
	}
	if(g_atomic_int_compare_and_exchange(&session->incall, 1, 0) && peer) {
		janus_refcount_decrease(&peer->ref);
	}

	//具体关闭流程有待完善

	gateway->close_pc(session->handle);

	gateway->close_pc(peer->handle);
	
}
static int janus_srtc_video_call_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len){
		return srtc_incoming_rtp_next(handle, video, buf,len);

}
static int janus_srtc_video_call_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len){
	return srtc_incoming_rtcp_next(handle, video, buf,len);

}
static int janus_srtc_video_call_incoming_data(janus_plugin_session *handle, char *buf, int len){
	return srtc_incoming_data_next(handle ,buf ,len);
}

void* janus_srtc_video_call_destory_plugin(void *ctx_){
	srtc_video_call_ctx_t *ctx =(srtc_video_call_ctx_t*)ctx_;
	//删除所有的session	
}

void* janus_srtc_video_call_create_plugin(const char *config_path){
	srtc_handle_call_next = srtc_handle_call;
	srtc_handle_call = janus_srtc_video_call_handle_call;
	srtc_handle_accept_next = srtc_handle_accept;
	srtc_handle_accept = janus_srtc_video_call_handle_accept;
	srtc_handle_hangup_next = srtc_handle_hangup;
	srtc_handle_hangup = janus_srtc_video_call_handle_hangup;
	srtc_incoming_rtp_next = srtc_incoming_rtp;
	srtc_incoming_rtp = janus_srtc_video_call_incoming_rtp;
	srtc_incoming_rtcp_next = srtc_incoming_rtcp;
	srtc_incoming_rtcp = janus_srtc_video_call_incoming_rtcp;
	srtc_incoming_data_next = srtc_incoming_data;
	srtc_incoming_data = janus_srtc_video_call_incoming_data;
	srtc_video_call_ctx_t *ctx =(srtc_video_call_ctx_t*)g_malloc(sizeof(srtc_video_call_ctx_t));
	ctx->sessions = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, (GDestroyNotify)janus_videocall_session_destroy);
	ctx->sessions_mutex = JANUS_MUTEX_INITIALIZER;
	return ctx;
}


