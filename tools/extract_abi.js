// check /abi directory exists, if not create it
const fs = require("fs");
const path = require("path");

const abiDir = path.join(__dirname, "..", "ABI");

if (!fs.existsSync(abiDir)) {
  fs.mkdirSync(abiDir);
  console.log("Created /ABI directory");
}

// read raw abi files
const rawAbiDir = path.join(__dirname, "..", "artifacts", "contracts");

const files = [
  "/CommodityToken/CommodityToken.sol/CommodityToken.json",
  "/CommodityToken/CommodityTokenProxy.sol/CommodityTokenProxy.json",
  "/CommodityTokenIssuer/CommodityTokenIssuer.sol/CommodityTokenIssuer.json",
  "/REdeemLock/RedeemLock.sol/RedeemLock.json",
];

files.forEach((file) => {
  const rawAbiPath = path.join(rawAbiDir, file);
  const rawAbi = JSON.parse(fs.readFileSync(rawAbiPath, "utf8"));
  const abi = rawAbi.abi;
  const abiPath = path.join(abiDir, path.basename(file, ".json") + ".abi.json");
  fs.writeFileSync(abiPath, JSON.stringify(abi, null, 2));
  console.log(`Extracted ABI for ${path.basename(file, ".json")}`);
});
