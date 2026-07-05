
const { exec } = require("child_process");
const path = require("path");
const fs = require("fs");

// ✅ Paths
const yaraPath = "C:\\Users\\aksha\\OneDrive\\Documents\\yara-projects\\yara-4.5.5-2368-win32\\yara64.exe";
const rulePath = path.join(__dirname, "rules", "ransomware_rule.yar");
const sampleDir = path.join(__dirname, "samples");

// 🔍 Scan each file in the samples folder
const files = fs.readdirSync(sampleDir);

console.log("🔍 Scanning started...");

files.forEach((file) => {
  const filePath = path.join(sampleDir, file);
  console.log(`\n📄 Checking file: ${file}`);

  // Run YARA via command line
  const cmd = `"${yaraPath}" "${rulePath}" "${filePath}"`;

  exec(cmd, (error, stdout, stderr) => {
    if (error) {
      console.log("❌ Error scanning file:", error.message);
      return;
    }

    if (stdout.trim()) {
      console.log("⚠️  ALERT! Suspicious ransomware patterns found!");
      console.log(stdout.trim());
    } else {
      console.log("✅ Safe file — no ransomware detected.");
    }
  });
});
