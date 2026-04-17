const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const path = require("path");

const app = express();
// Load env vars from server/.env only (do not use .env.local)
dotenv.config({ path: path.join(__dirname, ".env") });


app.use(cors());
app.use(express.json());

app.use("/api/auth",require("./routes/auth.routes"))
app.use("/api/repo",require("./routes/repo.routes"))

app.get('/',(req,res)=>{
    res.send("Homepage is working");
})


const connectDB = require("./config/dB")
const PORT = process.env.PORT || 5000;

connectDB()
    .then(() => {
        app.listen(PORT,()=>{
            console.log(`Server is listening at ${PORT}`);
        })
    })
    .catch(() => {
        process.exit(1);
    });