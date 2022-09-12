package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type User struct {
	Id       primitive.ObjectID `json:"id,omitempty"`
	Username string             `json:"username" validate:"required"`
	Password string             `json:"password" validate:"required"`
	Role     string             `json:"role" validate:"required"`
}

type Response struct {
	Message string      `json:"message"`
	Data    interface{} `json:"data,omit:empty"`
}

type LoginRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}
