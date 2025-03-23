const { ethers, upgrades } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contracts with the account:", deployer.address);

  const IncidentResponse = await ethers.getContractFactory("IncidentResponse");
  const contract = await upgrades.deployProxy(IncidentResponse, [], {
    initializer: "initialize"
  });
  await contract.waitForDeployment();
  const contractAddress = await contract.getAddress();
  console.log("IncidentResponse deployed to:", contractAddress);

  const adminRole = ethers.keccak256(ethers.toUtf8Bytes("ADMIN_ROLE"));
  const loggerRole = ethers.keccak256(ethers.toUtf8Bytes("LOGGER_ROLE"));
  const hasAdminRole = await contract.hasRole(adminRole, deployer.address);
  const hasLoggerRole = await contract.hasRole(loggerRole, deployer.address);
  console.log("Deployer has ADMIN_ROLE:", hasAdminRole);
  console.log("Deployer has LOGGER_ROLE:", hasLoggerRole);
}

main().catch((error) => {
  console.error("Deployment failed:", error);
  process.exit(1);
});