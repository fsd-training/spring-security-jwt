package com.ibm.ctube.jwt.dto;

public class MessageResponseDTO {
	private String message;

	public MessageResponseDTO(String message) {
	    this.message = message;
	  }

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}
}
