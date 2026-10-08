require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.28",
    settings: {
      evmVersion: "cancun",
      viaIR: false,
      optimizer: {
        enabled: true,
        runs: 100,
      },
    },
  },
  networks: {
    sepolia: {
      url: process.env.SEPOLIA_URL || "",
      accounts: [
        process.env.SEP_DEV_PRIVATE_KEY || "",
        process.env.SEP_UPGRADER_KEY || "",
        process.env.SEP_UPGRADE_AUDITOR_KEY || "",
      ],
    },
    arbSepolia: {
      url: process.env.ARB_SEPOLIA_URL || "",
      accounts: [process.env.ARB_SEP_DEV_PRIVATE_KEY || ""],
    },
  },
  etherscan: {
    apiKey: { sepolia: process.env.ETHERSCAN_API_KEY },
  },
};
