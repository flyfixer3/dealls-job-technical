package main

import (
	"golang/auth"
	"golang/configs"
	"golang/controllers"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	e := echo.New()
	configs.ConnectDB()

	jwtMiddleware := middleware.JWTWithConfig(middleware.JWTConfig{
		Claims:                  &auth.Claims{},
		SigningKey:              []byte(auth.GetJWTSecret()),
		TokenLookup:             "cookie:access-token",
		ErrorHandlerWithContext: auth.JWTErrorChecker,
	})

	e.POST("/login", controllers.Login)

	userGroup := e.Group("/users")
	adminGroup := e.Group("/admin")
	userGroup.Use(auth.TokenRefresherMiddleware, jwtMiddleware)
	adminGroup.Use(auth.TokenRefresherMiddleware, jwtMiddleware, auth.AdminMiddleware)

	//user or admin
	userGroup.GET("/find/:userId", controllers.GetUser)

	//only admin
	adminGroup.GET("/getAllUsers", controllers.GetUsers)
	adminGroup.POST("/addUser", controllers.AddUser)
	adminGroup.PUT("/editUser/:userId", controllers.EditUser)
	adminGroup.DELETE("/deleteUser/:userId", controllers.DeleteUser)

	e.Logger.Fatal(e.Start(":8100"))
}
