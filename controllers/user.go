package controllers

import (
	"context"
	"golang/auth"
	"golang/configs"
	"golang/models"
	"net/http"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var userCollection *mongo.Collection = configs.GetCollection(configs.DB, "Users")
var validate = validator.New()

func isCredValid(givenPwd, storedPwd string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(storedPwd), []byte(givenPwd)); err != nil {
		return false
	}
	return true
}

func GetUser(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	userId := c.Param("userId")
	var user models.User
	defer cancel()

	objId, _ := primitive.ObjectIDFromHex(userId)

	err := userCollection.FindOne(ctx, bson.M{"id": objId}).Decode(&user)

	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.Response{Message: "Error Internal"})
	}

	return c.JSON(http.StatusOK, user)
}

func DeleteUser(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	userId := c.Param("userId")
	defer cancel()

	objId, _ := primitive.ObjectIDFromHex(userId)

	result, err := userCollection.DeleteOne(ctx, bson.M{"id": objId})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.Response{Message: "Error Internal"})
	}

	if result.DeletedCount < 1 {
		return c.JSON(http.StatusNotFound, models.Response{Message: "Not Found"})

	}

	return c.JSON(http.StatusOK, result)
}

func EditUser(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	userId := c.Param("userId")
	var user models.User
	defer cancel()

	objId, _ := primitive.ObjectIDFromHex(userId)

	if err := c.Bind(&user); err != nil {
		return c.JSON(http.StatusBadRequest, models.Response{Message: "Error Bad Request"})
	}

	if validationErr := validate.Struct(&user); validationErr != nil {
		return c.JSON(http.StatusBadRequest, models.Response{Message: "Error Bad Request"})
	}

	update := bson.M{"username": user.Username, "password": user.Password, "role": user.Role}

	result, err := userCollection.UpdateOne(ctx, bson.M{"id": objId}, bson.M{"$set": update})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.Response{Message: "Error Internal"})
	}

	var updatedUser models.User
	if result.MatchedCount == 1 {
		err := userCollection.FindOne(ctx, bson.M{"id": objId}).Decode(&updatedUser)

		if err != nil {
			return c.JSON(http.StatusInternalServerError, models.Response{Message: "Error Internal"})
		}
	}

	return c.JSON(http.StatusOK, updatedUser)
}

func GetUsers(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var users []models.User
	defer cancel()

	results, err := userCollection.Find(ctx, bson.M{})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.Response{Message: "Error Internal"})
	}

	defer results.Close(ctx)
	for results.Next(ctx) {
		var singleUser models.User
		if err = results.Decode(&singleUser); err != nil {
			return c.JSON(http.StatusInternalServerError, models.Response{Message: "Error Internal"})
		}

		users = append(users, singleUser)
	}

	return c.JSON(http.StatusOK, users)
}

func AddUser(c echo.Context) error {
	var user models.User

	if err := c.Bind(&user); err != nil {
		return c.JSON(http.StatusBadRequest, models.Response{Message: err.Error()})
	}

	if err := validate.Struct(&user); err != nil {
		return c.JSON(http.StatusBadRequest, models.Response{Message: err.Error()})
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), 8)
	newUser := models.User{
		Id:       primitive.NewObjectID(),
		Username: user.Username,
		Password: string(hashedPassword),
		Role:     user.Role,
	}
	if err != nil {
		log.Errorf("Unable to hash the password: %v", err)
		return c.JSON(http.StatusInternalServerError, models.Response{Message: "Unable to process the password"})
	}

	result, err := userCollection.InsertOne(context.Background(), newUser)

	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.Response{Message: "Error While Inserting user"})
	}

	return c.JSON(http.StatusOK, models.Response(models.Response{Message: "Success", Data: result}))
}

func Login(c echo.Context) error {
	var userLogin models.LoginRequest
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var userData models.User
	defer cancel()

	if err := c.Bind(&userLogin); err != nil {
		return c.JSON(http.StatusBadRequest, models.Response{Message: err.Error()})
	}
	if err := validate.Struct(&userLogin); err != nil {
		return c.JSON(http.StatusBadRequest, models.Response{Message: err.Error()})
	}
	// result, err := userCollection.FindOne(context.Background(), bson.D{{"username", userLogin.Username}, {"password", userLogin.Password}})
	res := userCollection.FindOne(ctx, bson.M{"username": userLogin.Username})
	err := res.Decode(&userData)
	if err != nil && err != mongo.ErrNoDocuments {
		log.Errorf("Unable to decode retrieved user: %v", err)
		return c.JSON(http.StatusUnprocessableEntity, models.Response{Message: "Unable to decode retrieved user"})
	}

	if err == mongo.ErrNoDocuments {
		log.Errorf("User %s does not exist.", userLogin.Username)
		return c.JSON(http.StatusNotFound, models.Response{Message: "User does not exist"})
	}
	//validate the password
	if !isCredValid(userLogin.Password, userData.Password) {
		return c.JSON(http.StatusUnauthorized, models.Response{Message: "Credentials invalid"})
	}

	// If password is correct, generate tokens and set cookies.
	err = auth.GenerateTokensAndSetCookies(&userData, c)

	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Token is incorrect")
	}

	return c.JSON(http.StatusOK, models.User{Username: userData.Username})
}
