const express = require("express");
const multer = require("multer");
const { exec } = require("child_process");
const path = require("path");

const app = express();
app.use(express.static("public"));

// Upload folder
const upload = multer({ dest: "uploads/" });

// YARA paths
const yaraPath = "C:\\Users\\aksha\\OneDrive\\Documents\\yara-projects\\yara-4.5.5-2368-win64\\yara64.exe";
const rulePath = path.join(__dirname, "rules", "ransomware_rule.yar");

// Home page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Upload & Scan
app.post("/scan", upload.single("file"), (req, res) => {
  const filePath = req.file.path;

  const cmd = `"${yaraPath}" "${rulePath}" "${filePath}"`;

  exec(cmd, (error, stdout, stderr) => {
    if (stdout.trim()) {
      res.redirect(`/result.html?file=${req.file.originalname}&time=2.4`);

    } else {
      res.redirect(`/result.html?status=safe&file=${req.file.originalname}`);
    }
  });
});

// Start server
app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
