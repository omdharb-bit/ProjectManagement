import dotenv from "dotenv";

dotenv.config({
path:"./.env",
})

let myusername = process.env.username;

console.log("value:", myusername);

console.log("Start of the backend project");
