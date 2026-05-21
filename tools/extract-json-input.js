const fs = require("fs");
const path = require("path");

const buildInfoDir = path.join(__dirname, "..", "artifacts", "build-info");

const files = fs
  .readdirSync(buildInfoDir)
  .filter((file) => file.endsWith(".json"));

if (files.length === 0) {
  throw new Error(
    "No build-info files found. Run `npx hardhat compile` first.",
  );
}

// 가장 최근 build-info 선택
const latestFile = files
  .map((file) => ({
    file,
    time: fs.statSync(path.join(buildInfoDir, file)).mtime.getTime(),
  }))
  .sort((a, b) => b.time - a.time)[0].file;

const buildInfoPath = path.join(buildInfoDir, latestFile);
const buildInfo = JSON.parse(fs.readFileSync(buildInfoPath, "utf8"));

fs.writeFileSync(
  path.join(__dirname, "standard-json-input.json"),
  JSON.stringify(buildInfo.input, null, 2),
);

console.log(`Extracted input from ${latestFile}`);
console.log("Created standard-json-input.json");
