package com.alumni.management.chat.entity;

import java.time.LocalDateTime;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.index.CompoundIndexes;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Document(collection = "chat_messages")
@CompoundIndexes({
    @CompoundIndex(name = "conversation_time_idx", def = "{'conversationId': 1, 'timestamp': -1}"),
    @CompoundIndex(name = "sender_receiver_idx", def = "{'sender': 1, 'receiver': 1}"),
    @CompoundIndex(name = "sender_client_msg_unique_idx", def = "{'sender': 1, 'clientMessageId': 1}", unique = true, partialFilter = "{'clientMessageId': {'$type': 'string'}}")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ChatMessage {

	@Id
	private String id;

	@Indexed
	private String conversationId;

	@Indexed
	private String sender;

	@Indexed
	private String receiver;

	@Indexed
	private String clientMessageId;

	private String content;

	private MessageType type = MessageType.TEXT;

	private MessageStatus status = MessageStatus.SENT;

	private LocalDateTime timestamp = LocalDateTime.now();

	private LocalDateTime updatedAt;

	@JsonProperty("isRead")
	private boolean isRead = false;

	@JsonProperty("isRead")
	public boolean isRead() {
		return isRead || status == MessageStatus.READ;
	}

	public void setRead(boolean read) {
		this.isRead = read;
		if (read) {
			this.status = MessageStatus.READ;
		}
	}
}
