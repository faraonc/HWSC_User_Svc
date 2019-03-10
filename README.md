# hwsc-user-svc

## Purpose
Provides services to hwsc-app-gateway-svc for CRUD documents and user metadata in Azure CosmosDB

## Proto Contract
The proto file and compiled proto buffers are located in 
[hwsc-api-blocks](https://github.com/hwsc-org/hwsc-api-blocks/tree/master/int/hwsc-user-svc/proto)

###### Get Status
- Gets the current status of the service

###### CreateUser
- Creates a document in User MongoDB
- Returns the created document with password field set to empty string

###### DeleteUser
- Deletes a document in User MongoDB
- Returns the deleted document (TODO decide if we really need to return this to chrome)

###### UpdateUser
- Updates a document in User MongoDB
- Returns the updated document

###### AuthenticateUser
- Looks through documents in User MongoDB and perform email and password match
- Returns matched document

###### ListUsers
- Retrieves all the documents in User MongoDB
- Returns a collection of documents

###### GetUser
- Retrieves a document in User MongoDB, given UUID
- Returns found document

###### ShareDocument
- TODO

###### DeleteDocuments
- TODO

###### TODO
