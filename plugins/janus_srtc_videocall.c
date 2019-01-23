


//点对点的实现
#include "janus_srtc.h"

void* janus_srtc_video_call_create_plugin(janus_callbacks *callback, const char *config_path);
int janus_srtc_video_call_destory_plugin(void *ctx_);

srtc_handle_call_pt          srtc_handle_call_next;
srtc_handle_accept_pt          srtc_handle_accept_next;
srtc_handle_hangup_pt          srtc_handle_hangup_next;
srtc_incoming_rtp_pt          srtc_incoming_rtp_next;
srtc_incoming_rtcp_pt          srtc_incoming_rtcp_next;
srtc_incoming_data_pt          srtc_incoming_data_next;
static srtc_handle_message_pt          srtc_handle_message_next;



extern gboolean signal_server;
extern janus_plugin janus_srtc_plugin ;

srtc_module_t srtc_video_call_module = {
	0,
	janus_srtc_video_call_create_plugin,
	janus_srtc_video_call_destory_plugin,
	NULL
};

extern gboolean signal_server;

typedef struct {
	//存储相关模块的配置信息
	GHashTable *sessions;
	janus_mutex sessions_mutex;
	janus_callbacks *gateway;
}srtc_video_call_ctx_t;

typedef struct janus_srtc_videocall_session {
	janus_plugin_session *handle;
	gchar *username;

	gboolean has_audio;
	gboolean has_video;
	gboolean has_data;
	gboolean audio_active;
	gboolean video_active;
	janus_audiocodec acodec;/* Codec used for audio, if available */
	janus_videocodec vcodec;/* Codec used for video, if available */
	uint32_t bitrate;
	guint16 slowlink_count;
	janus_rtp_switching_context context;
	uint32_t ssrc[3];		/* Only needed in case VP8 (or H.264) simulcasting is involved */
	janus_rtp_simulcasting_context sim_context;
	int rtpmapid_extmap_id;	/* Only needed for debugging in case Firefox's RID-based simulcasting is involved */
	janus_vp8_simulcast_context vp8_context;
	janus_recorder *arc;	/* The Janus recorder instance for this user's audio, if enabled */
	janus_recorder *vrc;	/* The Janus recorder instance for this user's video, if enabled */
	janus_recorder *drc;	/* The Janus recorder instance for this user's data, if enabled */
	janus_mutex rec_mutex;	/* Mutex to protect the recorders from race conditions */

	struct janus_srtc_videocall_session *peer;
	volatile gint incall;
	volatile gint hangingup;
	volatile gint destroyed;
	janus_refcount ref;

}janus_srtc_videocall_session;

static void janus_srtc_videocall_session_free(const janus_refcount *session_ref) {
	janus_srtc_videocall_session *session = janus_refcount_containerof(session_ref, janus_srtc_videocall_session, ref);
	/* Remove the reference to the core plugin session */
	janus_refcount_decrease(&session->handle->ref);
	/* This session can be destroyed, free all the resources */
	g_free(session->username);
	g_free(session);
}

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
	srtc_video_call_ctx_t *ctx = srtc_get_module_ctx(srtc_video_call_module);
	if(ctx == NULL){
		return srtc_handle_call_next(handle, message, v);
	}
	if(handle->srtc_type == SERVER_A ){
		JANUS_LOG(LOG_ERR, "handle->srtc_type is SERVER_A \n", v->caller_name);
		return srtc_handle_call_next(handle, message, v);
	}else if(handle->srtc_type == SERVER_C){
		JANUS_LOG(LOG_ERR, "handle->srtc_type is SERVER_C something is error \n", v->caller_name);
		return srtc_handle_call_next(handle, message, v);
	}

	janus_mutex_lock(&ctx->sessions_mutex);
	if(g_hash_table_lookup(ctx->sessions, v->caller_name) != NULL) {
		janus_mutex_unlock(&ctx->sessions_mutex);
		JANUS_LOG(LOG_ERR, "Username '%s' already taken\n", v->caller_name);
		error_code = JANUS_VIDEOCALL_ERROR_USERNAME_TAKEN;
		g_snprintf(error_cause, 512, "Username '%s' already taken", v->caller_name);
		goto error;
	}
	janus_mutex_unlock(&ctx->sessions_mutex);
	janus_srtc_videocall_session *session = g_malloc0(sizeof(janus_srtc_videocall_session));
	session->handle = handle;
	session->has_audio = FALSE;
	session->has_video = FALSE;
	session->has_data = FALSE;
	session->audio_active = TRUE;
	session->video_active = TRUE;
	session->bitrate = 0;	/* No limit */
	session->peer = NULL;
	session->username = NULL;
	janus_rtp_switching_context_reset(&session->context);
	janus_rtp_simulcasting_context_reset(&session->sim_context);
	janus_vp8_simulcast_context_reset(&session->vp8_context);
	janus_mutex_init(&session->rec_mutex);
	g_atomic_int_set(&session->incall, 0);
	g_atomic_int_set(&session->hangingup, 0);
	g_atomic_int_set(&session->destroyed, 0);
	janus_refcount_init(&session->ref, janus_srtc_videocall_session_free);

	session->username = g_strdup(v->caller_name);
	janus_mutex_lock(&ctx->sessions_mutex);
	g_hash_table_insert(ctx->sessions, (gpointer)session->username, session);
	janus_mutex_unlock(&ctx->sessions_mutex);

	srtc_set_module_session(handle, srtc_video_call_module, session);
	if(!g_atomic_int_compare_and_exchange(&session->incall, 0, 1)) {
		JANUS_LOG(LOG_ERR, "Already in a call (but no peer?)\n");
		error_code = JANUS_VIDEOCALL_ERROR_ALREADY_IN_CALL;
		g_snprintf(error_cause, 512, "Already in a call (but no peer)");
		/* Hangup the call attempt of the user */
		ctx->gateway->close_pc(session->handle);
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
	srtc_video_call_ctx_t *ctx = srtc_get_module_ctx(srtc_video_call_module);
	if(ctx == NULL){
		return srtc_handle_call_next(handle, message, v);
	}
	const char *msg_sdp_type = json_string_value(json_object_get(v->jsep, "type"));
	const char *msg_sdp = json_string_value(json_object_get(v->jsep, "sdp"));

	janus_mutex_lock(&ctx->sessions_mutex);
	if(g_hash_table_lookup(ctx->sessions, v->callee_name) != NULL) {
		janus_mutex_unlock(&ctx->sessions_mutex);
		JANUS_LOG(LOG_ERR, "Username '%s' already taken\n", v->callee_name);
		error_code = JANUS_VIDEOCALL_ERROR_USERNAME_TAKEN;
		g_snprintf(error_cause, 512, "Username '%s' already taken", v->callee_name);
		goto error;
	}
	janus_mutex_unlock(&ctx->sessions_mutex);
	janus_srtc_videocall_session *session = g_malloc0(sizeof(janus_srtc_videocall_session));
	session->handle = handle;
	session->has_audio = FALSE;
	session->has_video = FALSE;
	session->has_data = FALSE;
	session->audio_active = TRUE;
	session->video_active = TRUE;
	session->bitrate = 0;	/* No limit */
	session->peer = NULL;
	session->username = NULL;
	janus_rtp_switching_context_reset(&session->context);
	janus_rtp_simulcasting_context_reset(&session->sim_context);
	janus_vp8_simulcast_context_reset(&session->vp8_context);
	janus_mutex_init(&session->rec_mutex);
	g_atomic_int_set(&session->incall, 0);
	g_atomic_int_set(&session->hangingup, 0);
	g_atomic_int_set(&session->destroyed, 0);
	janus_refcount_init(&session->ref, janus_srtc_videocall_session_free);
	srtc_set_module_session(handle, srtc_video_call_module, session);

	session->username = g_strdup(v->callee_name);
	janus_mutex_lock(&ctx->sessions_mutex);
	g_hash_table_insert(ctx->sessions, (gpointer)session->username, session);
	janus_mutex_unlock(&ctx->sessions_mutex);
	if(!g_atomic_int_compare_and_exchange(&session->incall, 0, 1)) {
		JANUS_LOG(LOG_ERR, "Already in a call (but no peer?)\n");
		error_code = JANUS_VIDEOCALL_ERROR_ALREADY_IN_CALL;
		g_snprintf(error_cause, 512, "Already in a call (but no peer)");
		/* Hangup the call attempt of the user */
		ctx->gateway->close_pc(session->handle);
		goto error;
	}
	//查找peer
	janus_mutex_lock(&ctx->sessions_mutex);
	janus_srtc_videocall_session *peer = g_hash_table_lookup(ctx->sessions, v->caller_name);
	if(peer == NULL || g_atomic_int_get(&peer->destroyed)) {
		g_atomic_int_set(&session->incall, 0);
		janus_mutex_unlock(&ctx->sessions_mutex);
		JANUS_LOG(LOG_ERR, "Username '%s' doesn't exist\n", v->caller_name);
		error_code = JANUS_VIDEOCALL_ERROR_NO_SUCH_USERNAME;
		g_snprintf(error_cause, 512, "Username '%s' doesn't exist", v->caller_name);
		/* Hangup the call attempt of the user */
		ctx->gateway->close_pc(session->handle);
		goto error;
	}
	session->peer = peer;
	peer->peer = session;
	/* If the call attempt proceeds we keep the references */
	janus_refcount_increase(&peer->ref);
	g_atomic_int_set(&peer->incall, 1);

	if(!msg_sdp) {
		janus_refcount_decrease(&peer->ref);
		JANUS_LOG(LOG_ERR, "Missing SDP\n");
		error_code = JANUS_VIDEOCALL_ERROR_MISSING_SDP;
		g_snprintf(error_cause, 512, "Missing SDP");
		goto error;
	}
	char error_str[512];
	janus_sdp *answer = janus_sdp_parse(msg_sdp, error_str, sizeof(error_str));
	if(answer == NULL) {
		janus_refcount_decrease(&peer->ref);
		JANUS_LOG(LOG_ERR, "Error parsing answer: %s\n", error_str);
		error_code = JANUS_VIDEOCALL_ERROR_INVALID_SDP;
		g_snprintf(error_cause, 512, "Error parsing answer: %s", error_str);
		goto error;
	}
	JANUS_LOG(LOG_VERB, "%s is accepting a call from %s\n", session->username, peer->username);
	JANUS_LOG(LOG_VERB, "This is involving a negotiation (%s) as well:\n%s\n", msg_sdp_type, msg_sdp);
	session->has_audio = (strstr(msg_sdp, "m=audio") != NULL);
	session->has_video = (strstr(msg_sdp, "m=video") != NULL);
	session->has_data = (strstr(msg_sdp, "DTLS/SCTP") != NULL);

	/* Check if this user will simulcast */
	json_t *msg_simulcast = json_object_get(v->jsep, "simulcast");
	if(msg_simulcast && janus_get_codec_pt(msg_sdp, "vp8") > 0) {
		JANUS_LOG(LOG_VERB, "VideoCall callee (%s) is going to do simulcasting\n", session->username);
		session->ssrc[0] = json_integer_value(json_object_get(msg_simulcast, "ssrc-0"));
		session->ssrc[1] = json_integer_value(json_object_get(msg_simulcast, "ssrc-1"));
		session->ssrc[2] = json_integer_value(json_object_get(msg_simulcast, "ssrc-2"));
	} else {
		session->ssrc[0] = 0;
		session->ssrc[1] = 0;
		session->ssrc[2] = 0;
		if(peer) {
			peer->ssrc[0] = 0;
			peer->ssrc[1] = 0;
			peer->ssrc[2] = 0;
		}
	}
	/* Check which codecs we ended up using */
	const char *acodec = NULL, *vcodec = NULL;
	janus_sdp_find_first_codecs(answer, &acodec, &vcodec);
	session->acodec = janus_audiocodec_from_name(acodec);
	session->vcodec = janus_videocodec_from_name(vcodec);
	if(session->acodec == JANUS_AUDIOCODEC_NONE) {
		session->has_audio = FALSE;
		if(peer)
			peer->has_audio = FALSE;
	} else if(peer) {
		peer->acodec = session->acodec;
	}
	if(session->vcodec == JANUS_VIDEOCODEC_NONE) {
		session->has_video = FALSE;
		if(peer)
			peer->has_video = FALSE;
	} else if(peer) {
		peer->vcodec = session->vcodec;
	}
	janus_sdp_destroy(answer);

	/* Send SDP to our peer */
	json_object_set_new(message, "eventtype", json_string("accept"));
	json_object_set_new(message, "srtc", json_string("event"));
	
	//重组message 形成accept 的answer todo
	int ret = ctx->gateway->push_event(peer->handle, &janus_srtc_plugin, NULL, message, v->jsep);

	/* Is simulcasting involved on either side? */
	if(session->ssrc[0] && session->ssrc[1]) {
		peer->sim_context.substream_target = 2; /* Let's aim for the highest quality */
		peer->sim_context.templayer_target = 2; /* Let's aim for all temporal layers */
	}
	if(peer->ssrc[0] && peer->ssrc[1]) {
		session->sim_context.substream_target = 2;	/* Let's aim for the highest quality */
		session->sim_context.templayer_target = 2;	/* Let's aim for all temporal layers */
	}

	janus_refcount_decrease(&peer->ref);
	return srtc_handle_accept_next(handle, message, v);
error:
	return -1;
}

static int
	janus_srtc_video_call_handle_hangup(janus_plugin_session *handle, json_t *message, janus_message_hangup_t *v)
{
	if(signal_server){
		return srtc_handle_call_next(handle, message, v);
	}
	srtc_video_call_ctx_t *ctx = srtc_get_module_ctx(srtc_video_call_module);
	if(ctx == NULL){
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

	/* Send SDP to our peer */
	json_object_set_new(message, "eventtype", json_string("hangup"));
	json_object_set_new(message, "srtc", json_string("event"));
	//重组message 形成accept 的answer todo
	int ret = ctx->gateway->push_event(peer->handle, &janus_srtc_plugin, NULL, message, NULL);

	/* Check if we still need to remove any reference */
	if(peer && g_atomic_int_compare_and_exchange(&peer->incall, 1, 0)) {
		janus_refcount_decrease(&session->ref);
	}
	if(g_atomic_int_compare_and_exchange(&session->incall, 1, 0) && peer) {
		janus_refcount_decrease(&peer->ref);
	}

	//具体关闭流程有待完善

	ctx->gateway->close_pc(session->handle);

	ctx->gateway->close_pc(peer->handle);



	return srtc_handle_call_next(handle, message, v);
}
static int janus_srtc_video_call_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len){
	if(handle == NULL || g_atomic_int_get(&handle->stopped) )//|| g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
			return;
	srtc_video_call_ctx_t *ctx = srtc_get_module_ctx(srtc_video_call_module);
	if(ctx == NULL){
		return srtc_incoming_rtp_next(handle, video, buf,len);
	}
	if(ctx->gateway) {
		/* Honour the audio/video active flags */
		janus_srtc_videocall_session *session = (janus_srtc_videocall_session *)handle->plugin_handle;
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		janus_srtc_videocall_session *peer = session->peer;
		if(!peer) {
			JANUS_LOG(LOG_ERR, "Session has no peer...\n");
			return;
		}
		if(g_atomic_int_get(&session->destroyed) || g_atomic_int_get(&peer->destroyed))
			return;
		if(video && session->video_active && session->rtpmapid_extmap_id != -1) {
			/* FIXME Just a way to debug Firefox simulcasting */
			janus_rtp_header *header = (janus_rtp_header *)buf;
			uint32_t seq_number = ntohs(header->seq_number);
			uint32_t timestamp = ntohl(header->timestamp);
			uint32_t ssrc = ntohl(header->ssrc);
			char sdes_item[16];
			if(janus_rtp_header_extension_parse_rtp_stream_id(buf, len, session->rtpmapid_extmap_id, sdes_item, sizeof(sdes_item)) == 0) {
				JANUS_LOG(LOG_DBG, "%"SCNu32"/%"SCNu16"/%"SCNu32"/%d: RTP stream ID extension: %s\n",
					ssrc, seq_number, timestamp, header->padding, sdes_item);
			}
		}
		if(video && session->video_active && session->ssrc[0] != 0) {
			/* Handle simulcast: backup the header information first */
			janus_rtp_header *header = (janus_rtp_header *)buf;
			uint32_t seq_number = ntohs(header->seq_number);
			uint32_t timestamp = ntohl(header->timestamp);
			uint32_t ssrc = ntohl(header->ssrc);
			/* Process this packet: don't relay if it's not the SSRC/layer we wanted to handle
			 * The caveat is that the targets in OUR simulcast context are the PEER's targets */
			gboolean relay = janus_rtp_simulcasting_context_process_rtp(&peer->sim_context,
				buf, len, session->ssrc, session->vcodec, &peer->context);
			/* Do we need to drop this? */
			if(!relay)
				return;
			/* Any event we should notify? */
			if(peer->sim_context.changed_substream) {
				/* Notify the user about the substream change */
				json_t *event = json_object();
				json_object_set_new(event, "videocall", json_string("event"));
				json_t *result = json_object();
				json_object_set_new(result, "event", json_string("simulcast"));
				json_object_set_new(result, "videocodec", json_string(janus_videocodec_name(session->vcodec)));
				json_object_set_new(result, "substream", json_integer(session->sim_context.substream));
				json_object_set_new(event, "result", result);
				ctx->gateway->push_event(peer->handle, &janus_srtc_plugin, NULL, event, NULL);
				json_decref(event);
			}
			if(peer->sim_context.need_pli) {
				/* Send a PLI */
				JANUS_LOG(LOG_VERB, "We need a PLI for the simulcast context\n");
				char rtcpbuf[12];
				memset(rtcpbuf, 0, 12);
				janus_rtcp_pli((char *)&rtcpbuf, 12);
				ctx->gateway->relay_rtcp(session->handle, 1, rtcpbuf, 12);
			}
			if(peer->sim_context.changed_temporal) {
				/* Notify the user about the temporal layer change */
				json_t *event = json_object();
				json_object_set_new(event, "videocall", json_string("event"));
				json_t *result = json_object();
				json_object_set_new(result, "event", json_string("simulcast"));
				json_object_set_new(result, "videocodec", json_string(janus_videocodec_name(session->vcodec)));
				json_object_set_new(result, "temporal", json_integer(session->sim_context.templayer));
				json_object_set_new(event, "result", result);
				ctx->gateway->push_event(peer->handle, &janus_srtc_plugin, NULL, event, NULL);
				json_decref(event);
			}
			/* If we got here, update the RTP header and send the packet */
			janus_rtp_header_update(header, &peer->context, TRUE, 4500);
			if(session->vcodec == JANUS_VIDEOCODEC_VP8) {
				int plen = 0;
				char *payload = janus_rtp_payload(buf, len, &plen);
				janus_vp8_simulcast_descriptor_update(payload, plen, &peer->vp8_context, peer->sim_context.changed_substream);
			}
			/* Save the frame if we're recording (and make sure the SSRC never changes even if the substream does) */
			header->ssrc = htonl(1);
			janus_recorder_save_frame(session->vrc, buf, len);
			/* Send the frame back */
			ctx->gateway->relay_rtp(peer->handle, video, buf, len);
			/* Restore header or core statistics will be messed up */
			header->ssrc = htonl(ssrc);
			header->timestamp = htonl(timestamp);
			header->seq_number = htons(seq_number);
		} else {
			if((!video && session->audio_active) || (video && session->video_active)) {
				/* Save the frame if we're recording */
				janus_recorder_save_frame(video ? session->vrc : session->arc, buf, len);
				/* Forward the packet to the peer */
				ctx->gateway->relay_rtp(peer->handle, video, buf, len);
			}
		}
	}

	return srtc_incoming_rtp_next(handle, video, buf,len);

}
static int janus_srtc_video_call_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len){
	if(handle == NULL || g_atomic_int_get(&handle->stopped))// || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	srtc_video_call_ctx_t *ctx = srtc_get_module_ctx(srtc_video_call_module);
	if(ctx == NULL){
		return srtc_incoming_rtcp_next(handle, video, buf,len);
	}
	if(ctx->gateway) {
		janus_srtc_videocall_session *session = (janus_srtc_videocall_session *)handle->plugin_handle;
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		janus_srtc_videocall_session *peer = session->peer;
		if(!peer) {
			JANUS_LOG(LOG_ERR, "Session has no peer...\n");
			return;
		}
		if(g_atomic_int_get(&session->destroyed) || g_atomic_int_get(&peer->destroyed))
			return;
		guint32 bitrate = janus_rtcp_get_remb(buf, len);
		if(bitrate > 0) {
			/* If a REMB arrived, make sure we cap it to our configuration, and send it as a video RTCP */
			if(session->bitrate > 0)
				janus_rtcp_cap_remb(buf, len, session->bitrate);
			ctx->gateway->relay_rtcp(peer->handle, 1, buf, len);
			return;
		}
		ctx->gateway->relay_rtcp(peer->handle, video, buf, len);
	}

	return srtc_incoming_rtcp_next(handle, video, buf,len);

}
static int janus_srtc_video_call_incoming_data(janus_plugin_session *handle, char *buf, int len){
	if(handle == NULL || g_atomic_int_get(&handle->stopped))// || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;

	srtc_video_call_ctx_t *ctx = srtc_get_module_ctx(srtc_video_call_module);
	if(ctx == NULL){
		return srtc_incoming_data_next(handle ,buf ,len);
	}
	if(ctx->gateway) {
		janus_srtc_videocall_session *session = (janus_srtc_videocall_session *)handle->plugin_handle;
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		janus_srtc_videocall_session *peer = session->peer;
		if(!peer) {
			JANUS_LOG(LOG_ERR, "Session has no peer...\n");
			return;
		}
		if(g_atomic_int_get(&session->destroyed) || g_atomic_int_get(&peer->destroyed))
			return;
		if(buf == NULL || len <= 0)
			return;
		char *text = g_malloc(len+1);
		memcpy(text, buf, len);
		*(text+len) = '\0';
		JANUS_LOG(LOG_VERB, "Got a DataChannel message (%zu bytes) to forward: %s\n", strlen(text), text);
		/* Save the frame if we're recording */
		janus_recorder_save_frame(session->drc, buf, len);
		/* Forward the packet to the peer */
		ctx->gateway->relay_data(peer->handle, text, strlen(text));
		g_free(text);
	}

	return srtc_incoming_data_next(handle ,buf ,len);
}

int janus_srtc_video_call_destory_plugin(void *ctx_){
	srtc_video_call_ctx_t *ctx =(srtc_video_call_ctx_t*)ctx_;
	//删除所有的session
}

int janus_srtc_video_call_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep){
	//1、判断appkey的合法性
	//2、存储username 和当前服务器的外网IP
	srtc_video_call_ctx_t *ctx = srtc_get_module_ctx(srtc_video_call_module);
	if(ctx == NULL){
		return srtc_handle_message_next(handle, transaction, message, jsep);
	}
	json_t *root = json_object_get(message, "srtc");
	const gchar *root_text = json_string_value(root);
	if(handle->srtc_type == SERVER_A || handle->srtc_type == SERVER_C){
		if(!strcasecmp(root_text, "event")){
			int ret = ctx->gateway->push_event(handle, &janus_srtc_plugin, NULL, message, NULL);
			return srtc_handle_message_next(handle, transaction, message, jsep);
		}
	}
	if(handle->srtc_type == SERVER_A){
		return srtc_handle_message_next(handle, transaction, message, jsep);
	}else if(handle->srtc_type == SERVER_C){
		return srtc_handle_message_next(handle, transaction, message, jsep);
	}
	else{
		janus_srtc_videocall_session *session = srtc_get_module_session(handle, srtc_video_call_module);
		janus_srtc_videocall_session *peer = session->peer;
		if(peer == NULL) {
			JANUS_LOG(LOG_WARN, "No call to hangup\n");
			return srtc_handle_message_next(handle, transaction, message, jsep);
		}
		if(!strcasecmp(root_text, "trickle")|| !strcasecmp(root_text, "refuse")){
			json_object_set_new(message, "eventtype", json_string(root_text));
			json_object_set_new(message, "srtc", json_string("event"));
		}
		int ret = ctx->gateway->push_event(peer->handle, &janus_srtc_plugin, NULL, message, NULL);
	}
	return srtc_handle_message_next(handle, transaction, message, jsep);
}

void* janus_srtc_video_call_create_plugin(janus_callbacks *callback, const char *config_path){
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
	srtc_handle_message_next = srtc_handle_message;
	srtc_handle_message = janus_srtc_video_call_handle_message;
	srtc_video_call_ctx_t *ctx =(srtc_video_call_ctx_t*)g_malloc(sizeof(srtc_video_call_ctx_t));
	memset(ctx, 0,sizeof(srtc_video_call_ctx_t));
	ctx->gateway = callback;
	ctx->sessions = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, (GDestroyNotify)janus_srtc_videocall_session_destroy);
	return ctx;
}


