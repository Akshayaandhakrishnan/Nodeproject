const express = require("express");
const multer = require("multer");
const path = require("path");
const { exec } = require("child_process");
const fs = require("fs");

const app = express();
const PORT = 3000;

// Paths
const yaraPath = "C:\\Users\\aksha\\OneDrive\\Documents\\yara-projects\\yara-4.5.5-2368-win32\\yara64.exe";
const rulePath = path.join(__dirname, "rules", "ransomware_rule.yar");

// File upload settings
const upload = multer({ dest: "uploads/" });

// Serve frontend
app.use(express.static("public"));

// Scan uploaded file
app.post("/scan", upload.single("file"), (req, res) => {
  const filePath = req.file.path;
  const cmd = `"${yaraPath}" "${rulePath}" "${filePath}"`;

  exec(cmd, (error, stdout, stderr) => {
    fs.unlinkSync(filePath); // delete uploaded file

    let resultHTML = `
      <style>
        body {
          font-family: Arial, sans-serif;
          background: #f4f4f9;
          text-align: center;
          padding-top: 120px;
        }
        .box {
          background: #fff;
          padding: 40px;
          width: 450px;
          margin: auto;
          border-radius: 12px;
          box-shadow: 0 4px 10px rgba(0,0,0,0.1);
        }
        .safe {
          color: green;
          font-size: 22px;
          font-weight: bold;
        }
        .danger {
          color: red;
          font-size: 22px;
          font-weight: bold;
        }
        a {
          text-decoration: none;
          color: #007bff;
          display: inline-block;
          margin-top: 20px;
        }
        pre {
          background: #f8f8f8;
          padding: 10px;
          border-radius: 8px;
          text-align: left;
          width: 90%;
          margin: 10px auto;
        }
      </style>
      <div class="box">
    `;

    if (error) {
      resultHTML += `<p class="danger">❌ Error scanning file: ${error.message}</p>`;
    } else if (stdout.trim()) {
      resultHTML += `
        <p class="danger">⚠️ ALERT! Suspicious ransomware patterns found!</p>
        <pre>${stdout}</pre>
      `;
    } else {
      resultHTML += `<p class="safe">✅ Safe file — No ransomware detected.</p>`;
    }

    resultHTML += `<a href="/">⬅ Go Back</a></div>`;
    res.send(resultHTML);
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
