const { ethers } = require("hardhat");
const { expect, assert } = require("chai");
const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");

function todo(msg) {
  assert.fail(`[TODO] ${msg}`);
}

async function grantRole(c, r, a) {
  const tx = await c.grantRole(r, a);
  await tx.wait();
}

async function mint(c, defaultAdmin, to, amount) {
  const MINTER_ROLE = await c.MINTER_ROLE();

  const grtx = await grantRole(c, MINTER_ROLE, defaultAdmin.address);

  const mintTx = await c.connect(defaultAdmin).mint(to, amount);
  await mintTx.wait();

  const rvtx = await c.revokeRole(MINTER_ROLE, defaultAdmin.address);
  await rvtx.wait();
}

async function approve(c, owner, spender, amount) {
  const approveTx = await c.connect(owner).approve(spender, amount);
  await approveTx.wait();
}

async function pause(c, pauser) {
  const PAUSER_ROLE = await c.PAUSER_ROLE();

  const grtx = await grantRole(c, PAUSER_ROLE, pauser.address);

  const pauseTx = await c.connect(pauser).pause();
  await pauseTx.wait();
}

describe("KGLD All Features", function () {
  async function deployFixture() {
    let implFac, proxyFac;
    let tokenProxy, proxy, impl;
    const [
      deployer,
      upgrader,
      pauser,
      vaultMinter,
      minter,
      burner,
      riskManager,
      mintApprover,
      upgradeAuditor,
      w1,
      w2,
      w3,
      w4,
    ] = await ethers.getSigners();

    implFac = await ethers.getContractFactory("CommodityToken");
    proxyFac = await ethers.getContractFactory("CommodityTokenProxy");

    impl = await implFac.deploy();
    await impl.waitForDeployment();

    const initData = impl.interface.encodeFunctionData("initialize", [
      deployer.address,
      "Korea Gold-Backed Token",
      "KGLD",
    ]);

    proxy = await proxyFac.deploy(impl.target, initData);
    await proxy.waitForDeployment();

    tokenProxy = implFac.attach(proxy.target);
    return {
      tokenProxy,
      proxy,
      deployer,
      upgrader,
      pauser,
      vaultMinter,
      minter,
      burner,
      riskManager,
      mintApprover,
      upgradeAuditor,
      implFac,
      wallets: [w1, w2, w3, w4],
    };
  }

  describe("ERC20 Basic", () => {
    describe("Initialization", () => {
      it("✨ name : Korea Gold-Backed Token", async () => {
        const { tokenProxy } = await loadFixture(deployFixture);
        expect(await tokenProxy.name()).to.equal("Korea Gold-Backed Token");
      });

      it("✨ symbol : KGLD", async () => {
        const { tokenProxy } = await loadFixture(deployFixture);
        expect(await tokenProxy.symbol()).to.equal("KGLD");
      });

      it("✨ decimals : 18", async () => {
        const { tokenProxy } = await loadFixture(deployFixture);
        expect(await tokenProxy.decimals()).to.equal(18);
      });

      it("✨ InitialAdmin(DEFAULT_ADMIN_ROLE)", async () => {
        const { tokenProxy, deployer } = await loadFixture(deployFixture);
        const DEFAULT_ADMIN_ROLE = await tokenProxy.DEFAULT_ADMIN_ROLE();
        expect(
          await tokenProxy.hasRole(DEFAULT_ADMIN_ROLE, deployer.address),
        ).to.equal(true);
      });
    });
    describe("Mint / Burn", () => {
      it("✨ Only MINTER_ROLE can call mint()", async () => {
        const { tokenProxy, minter, wallets } = await loadFixture(
          deployFixture,
        );
        const amount = ethers.parseEther("10");

        const w1BalBef = await tokenProxy.balanceOf(wallets[0].address);
        expect(w1BalBef).to.equal(0);

        // Grant MINTER_ROLE to minter
        await grantRole(
          tokenProxy,
          await tokenProxy.MINTER_ROLE(),
          minter.address,
        );

        // Execute mint tx
        const mintTx = await tokenProxy
          .connect(minter)
          .mint(wallets[0].address, amount);
        await mintTx.wait();

        const w1BalAft = await tokenProxy.balanceOf(wallets[0].address);
        expect(w1BalAft).to.equal(amount);

        // Not authorized account should be rejected
        await expect(
          tokenProxy.connect(wallets[1]).mint(wallets[1].address, amount),
        ).to.be.revertedWithCustomError(
          tokenProxy,
          "AccessControlUnauthorizedAccount",
        );
      });

      it("✨ Only BURNER_ROLE can call burn()", async () => {
        const { tokenProxy, deployer, burner, wallets } = await loadFixture(
          deployFixture,
        );

        await mint(
          tokenProxy,
          deployer,
          burner.address,
          ethers.parseEther("10"),
        );

        expect(await tokenProxy.balanceOf(burner.address)).to.equal(
          ethers.parseEther("10"),
        );

        // Grant BURNER_ROLE to burner
        await grantRole(
          tokenProxy,
          await tokenProxy.BURNER_ROLE(),
          burner.address,
        );

        // Execute burn tx
        const burnTx = await tokenProxy
          .connect(burner)
          .burn(ethers.parseEther("5"));
        await burnTx.wait();

        const burnerBal = await tokenProxy.balanceOf(burner.address);
        expect(burnerBal).to.equal(ethers.parseEther("5"));

        const totalSupply = await tokenProxy.totalSupply();
        expect(totalSupply).to.equal(ethers.parseEther("5"));

        // Not authorized account should be rejected
        await expect(
          tokenProxy.connect(wallets[1]).burn(ethers.parseEther("1")),
        ).to.be.revertedWithCustomError(
          tokenProxy,
          "AccessControlUnauthorizedAccount",
        );
      });
      it("✨ Burn should fail when the balance is insufficient", async () => {
        const { tokenProxy, deployer, burner } = await loadFixture(
          deployFixture,
        );

        await mint(
          tokenProxy,
          deployer,
          burner.address,
          ethers.parseEther("10"),
        );

        // Grant BURNER_ROLE to burner
        await grantRole(
          tokenProxy,
          await tokenProxy.BURNER_ROLE(),
          burner.address,
        );

        // Execute burn tx with insufficient balance
        await expect(
          tokenProxy.connect(burner).burn(ethers.parseEther("20")),
        ).to.be.revertedWithCustomError(tokenProxy, "ERC20InsufficientBalance");
      });
    });
    describe("Transfer", () => {
      it("✨ Success when the balance is sufficient", async () => {
        const { tokenProxy, deployer, wallets } = await loadFixture(
          deployFixture,
        );

        const amount = ethers.parseEther("10");
        await mint(tokenProxy, deployer, wallets[0].address, amount);

        const w0Bal = await tokenProxy.balanceOf(wallets[0].address);
        expect(w0Bal).to.equal(amount);

        const transferAmount = ethers.parseEther("5");

        // Execute transfer tx
        const transferTx = await tokenProxy
          .connect(wallets[0])
          .transfer(wallets[1].address, transferAmount);
        await transferTx.wait();

        const w1Bal = await tokenProxy.balanceOf(wallets[1].address);
        expect(w1Bal).to.equal(transferAmount);
      });
      it("✨ Revert when the balance is insufficient", async () => {
        const { tokenProxy, deployer, wallets } = await loadFixture(
          deployFixture,
        );

        const amount = ethers.parseEther("10");
        await mint(tokenProxy, deployer, wallets[0].address, amount);

        const w0Bal = await tokenProxy.balanceOf(wallets[0].address);
        expect(w0Bal).to.equal(amount);

        const transferAmount = ethers.parseEther("20");

        // Execute transfer tx
        await expect(
          tokenProxy
            .connect(wallets[0])
            .transfer(wallets[1].address, transferAmount),
        ).to.be.revertedWithCustomError(tokenProxy, "ERC20InsufficientBalance");
      });
    });
    describe("TransferFrom", () => {
      it("✨ Success when allowance is sufficient", async () => {
        const { tokenProxy, deployer, wallets } = await loadFixture(
          deployFixture,
        );

        const amount = ethers.parseEther("10");
        await mint(tokenProxy, deployer, wallets[0].address, amount);

        const w0Bal = await tokenProxy.balanceOf(wallets[0].address);
        expect(w0Bal).to.equal(amount);

        const transferAmount = ethers.parseEther("5");

        const approveTx = await tokenProxy
          .connect(wallets[0])
          .approve(wallets[1].address, transferAmount);
        await approveTx.wait();

        expect(
          await tokenProxy.allowance(wallets[0].address, wallets[1].address),
        ).to.equal(transferAmount);

        // Execute transfer tx
        const transferFromTx = await tokenProxy
          .connect(wallets[1])
          .transferFrom(wallets[0].address, wallets[1].address, transferAmount);
        await transferFromTx.wait();

        const w1Bal = await tokenProxy.balanceOf(wallets[1].address);
        expect(w1Bal).to.equal(transferAmount);

        const allowanceAfter = await tokenProxy.allowance(
          wallets[0].address,
          wallets[1].address,
        );
        expect(allowanceAfter).to.equal(0);
      });
      it("✨ Revert when the allowance is insufficient", async () => {
        const { tokenProxy, deployer, wallets } = await loadFixture(
          deployFixture,
        );

        const mintAmount = ethers.parseEther("10");
        await mint(tokenProxy, deployer, wallets[0].address, mintAmount);

        const w0Bal = await tokenProxy.balanceOf(wallets[0].address);
        expect(w0Bal).to.equal(mintAmount);

        const approveAmount = ethers.parseEther("10");

        const approveTx = await tokenProxy
          .connect(wallets[0])
          .approve(wallets[1].address, approveAmount);
        await approveTx.wait();

        expect(
          await tokenProxy.allowance(wallets[0].address, wallets[1].address),
        ).to.equal(approveAmount);

        const transferAmount = ethers.parseEther("20");

        await expect(
          tokenProxy
            .connect(wallets[1])
            .transferFrom(
              wallets[0].address,
              wallets[1].address,
              transferAmount,
            ),
        ).to.be.revertedWithCustomError(
          tokenProxy,
          "ERC20InsufficientAllowance",
        );
      });
    });
    describe("Allowance / Approval", () => {
      it("✨ Allowance should be increased when approve() is called", async () => {
        const { tokenProxy, deployer, wallets } = await loadFixture(
          deployFixture,
        );

        const allowanceBefore = await tokenProxy.allowance(
          wallets[0].address,
          wallets[1].address,
        );
        expect(allowanceBefore).to.equal(0);
        const approveAmount = ethers.parseEther("10");
        const approveTx1 = await tokenProxy
          .connect(wallets[0])
          .approve(wallets[1].address, approveAmount);
        await approveTx1.wait();

        const allowanceAfter = await tokenProxy.allowance(
          wallets[0].address,
          wallets[1].address,
        );
        expect(allowanceAfter).to.equal(approveAmount);
      });
      it("✨ Allowance should be overridden when approve() is called again", async () => {
        const { tokenProxy, deployer, wallets } = await loadFixture(
          deployFixture,
        );

        const allowanceBefore = await tokenProxy.allowance(
          wallets[0].address,
          wallets[1].address,
        );
        expect(allowanceBefore).to.equal(0);
        const approveAmount = ethers.parseEther("10");
        const approveTx1 = await tokenProxy
          .connect(wallets[0])
          .approve(wallets[1].address, approveAmount);
        await approveTx1.wait();

        const allowanceAfter = await tokenProxy.allowance(
          wallets[0].address,
          wallets[1].address,
        );
        expect(allowanceAfter).to.equal(approveAmount);

        const approveAmount2 = ethers.parseEther("5");
        const approveTx2 = await tokenProxy
          .connect(wallets[0])
          .approve(wallets[1].address, approveAmount2);
        await approveTx2.wait();

        const allowanceAfter2 = await tokenProxy.allowance(
          wallets[0].address,
          wallets[1].address,
        );
        expect(allowanceAfter2).to.equal(approveAmount2);
      });
    });
  });

  describe("Compliance / Risk", () => {
    describe("Pause/Unpause", () => {
      it("✨ only PAUSER_ROLE can call pause()", async () => {
        const { tokenProxy, deployer, pauser, wallets } = await loadFixture(
          deployFixture,
        );

        const grtx = await grantRole(
          tokenProxy,
          await tokenProxy.PAUSER_ROLE(),
          pauser.address,
        );

        // no role account should be rejected
        await expect(
          tokenProxy.connect(wallets[0]).pause(),
        ).to.be.revertedWithCustomError(
          tokenProxy,
          "AccessControlUnauthorizedAccount",
        );

        expect(
          await tokenProxy.hasRole(
            await tokenProxy.PAUSER_ROLE(),
            pauser.address,
          ),
        ).to.equal(true);

        const pauseTx = await tokenProxy.connect(pauser).pause();
        await pauseTx.wait();

        const paused = await tokenProxy.paused();
        expect(paused).to.equal(true);
      });
      it("✨ transfer should fail when paused", async () => {
        const { tokenProxy, deployer, pauser, wallets } = await loadFixture(
          deployFixture,
        );

        const amount = ethers.parseEther("10");
        await mint(tokenProxy, deployer, wallets[0].address, amount);

        await pause(tokenProxy, pauser);

        const paused = await tokenProxy.paused();
        expect(paused).to.equal(true);

        await expect(
          tokenProxy
            .connect(wallets[0])
            .transfer(wallets[1].address, ethers.parseEther("1")),
        ).to.be.revertedWithCustomError(tokenProxy, "EnforcedPause");
      });
      it("✨ transferFrom should fail when paused", async () => {
        const { tokenProxy, deployer, pauser, wallets } = await loadFixture(
          deployFixture,
        );

        const amount = ethers.parseEther("10");
        await mint(tokenProxy, deployer, wallets[0].address, amount);

        const approveTx = await tokenProxy
          .connect(wallets[0])
          .approve(wallets[1].address, ethers.parseEther("1"));
        await approveTx.wait();

        await pause(tokenProxy, pauser);

        const paused = await tokenProxy.paused();
        expect(paused).to.equal(true);

        await expect(
          tokenProxy
            .connect(wallets[0])
            .transferFrom(
              wallets[0].address,
              wallets[1].address,
              ethers.parseEther("1"),
            ),
        ).to.be.revertedWithCustomError(tokenProxy, "EnforcedPause");
      });
      it("✨ approve should fail when paused", async () => {
        const { tokenProxy, deployer, pauser, wallets } = await loadFixture(
          deployFixture,
        );

        const amount = ethers.parseEther("10");
        await mint(tokenProxy, deployer, wallets[0].address, amount);

        await pause(tokenProxy, pauser);
        const paused = await tokenProxy.paused();
        expect(paused).to.equal(true);

        await expect(
          tokenProxy
            .connect(wallets[0])
            .approve(wallets[1].address, ethers.parseEther("1")),
        ).to.be.revertedWithCustomError(tokenProxy, "EnforcedPause");
      });
      it("✨ revoke allowance is available even when paused", async () => {
        const { tokenProxy, deployer, pauser, wallets } = await loadFixture(
          deployFixture,
        );

        const amount = ethers.parseEther("10");
        await mint(tokenProxy, deployer, wallets[0].address, amount);

        const approveTx = await tokenProxy
          .connect(wallets[0])
          .approve(wallets[1].address, amount);
        await approveTx.wait();

        expect(
          await tokenProxy.allowance(wallets[0].address, wallets[1].address),
        ).to.equal(amount);

        await pause(tokenProxy, pauser);
        const paused = await tokenProxy.paused();
        expect(paused).to.equal(true);

        const revokeTx = await tokenProxy
          .connect(wallets[0])
          .approve(wallets[1].address, 0);
        await revokeTx.wait();

        const allowanceAfter = await tokenProxy.allowance(
          wallets[0].address,
          wallets[1].address,
        );
        expect(allowanceAfter).to.equal(0);
      });
      it("✨ only PAUSER_ROLE can call unpause()", async () => {
        const { tokenProxy, deployer, pauser, wallets } = await loadFixture(
          deployFixture,
        );

        await pause(tokenProxy, pauser);
        const paused = await tokenProxy.paused();
        expect(paused).to.equal(true);

        await expect(
          tokenProxy.connect(wallets[0]).unpause(),
        ).to.be.revertedWithCustomError(
          tokenProxy,
          "AccessControlUnauthorizedAccount",
        );

        const unpauseTx = await tokenProxy.connect(pauser).unpause();
        await unpauseTx.wait();

        const pausedAfter = await tokenProxy.paused();
        expect(pausedAfter).to.equal(false);
      });
      it("✨ transfer should succeed after unpaused", async () => {
        const { tokenProxy, deployer, pauser, wallets } = await loadFixture(
          deployFixture,
        );

        await mint(
          tokenProxy,
          deployer,
          wallets[0].address,
          ethers.parseEther("10"),
        );

        await pause(tokenProxy, pauser);
        const paused = await tokenProxy.paused();
        expect(paused).to.equal(true);

        const unpauseTx = await tokenProxy.connect(pauser).unpause();
        await unpauseTx.wait();

        const pausedAfter = await tokenProxy.paused();
        expect(pausedAfter).to.equal(false);

        const w1BalBefore = await tokenProxy.balanceOf(wallets[1].address);

        const amount = ethers.parseEther("1");
        const transferTx = await tokenProxy
          .connect(wallets[0])
          .transfer(wallets[1].address, amount);
        await transferTx.wait();

        const w1BalAfter = await tokenProxy.balanceOf(wallets[1].address);
        expect(w1BalAfter - w1BalBefore).to.equal(amount);
      });
      it("✨ transferFrom should succeed after unpaused", async () => {
        const { tokenProxy, deployer, pauser, wallets } = await loadFixture(
          deployFixture,
        );

        await mint(
          tokenProxy,
          deployer,
          wallets[0].address,
          ethers.parseEther("10"),
        );

        await pause(tokenProxy, pauser);
        const paused = await tokenProxy.paused();
        expect(paused).to.equal(true);

        const unpauseTx = await tokenProxy.connect(pauser).unpause();
        await unpauseTx.wait();

        const pausedAfter = await tokenProxy.paused();
        expect(pausedAfter).to.equal(false);

        const w1BalBefore = await tokenProxy.balanceOf(wallets[1].address);

        const amount = ethers.parseEther("1");

        const approveTx = await tokenProxy
          .connect(wallets[0])
          .approve(wallets[1].address, amount);
        await approveTx.wait();

        const transferTx = await tokenProxy
          .connect(wallets[1])
          .transferFrom(wallets[0].address, wallets[1].address, amount);
        await transferTx.wait();

        const w1BalAfter = await tokenProxy.balanceOf(wallets[1].address);
        expect(w1BalAfter - w1BalBefore).to.equal(amount);
      });
      it("✨ approve should succeed after unpaused", async () => {
        const { tokenProxy, deployer, pauser, wallets } = await loadFixture(
          deployFixture,
        );

        await mint(
          tokenProxy,
          deployer,
          wallets[0].address,
          ethers.parseEther("10"),
        );

        await pause(tokenProxy, pauser);
        const paused = await tokenProxy.paused();
        expect(paused).to.equal(true);

        const unpauseTx = await tokenProxy.connect(pauser).unpause();
        await unpauseTx.wait();

        const pausedAfter = await tokenProxy.paused();
        expect(pausedAfter).to.equal(false);
        const amount = ethers.parseEther("1");

        const approveTx = await tokenProxy
          .connect(wallets[0])
          .approve(wallets[1].address, amount);
        await approveTx.wait();

        const allowanceAfter = await tokenProxy.allowance(
          wallets[0].address,
          wallets[1].address,
        );

        expect(allowanceAfter).to.equal(amount);
      });
    });
    describe("Freeze/Unfreeze", () => {
      it("✨ only RISK_MANAGER_ROLE can call freeze()", async () => {
        const { tokenProxy, deployer, riskManager, wallets } =
          await loadFixture(deployFixture);

        await expect(
          tokenProxy.connect(wallets[0]).freeze(wallets[1].address),
        ).to.be.revertedWithCustomError(
          tokenProxy,
          "AccessControlUnauthorizedAccount",
        );

        await grantRole(
          tokenProxy,
          await tokenProxy.RISK_MANAGER_ROLE(),
          riskManager.address,
        );

        expect(
          await tokenProxy.hasRole(
            await tokenProxy.RISK_MANAGER_ROLE(),
            riskManager.address,
          ),
        ).to.equal(true);

        const freezeTx = await tokenProxy
          .connect(riskManager)
          .freeze(wallets[1].address);
        await freezeTx.wait();

        const isFrozen = await tokenProxy.hasRole(
          await tokenProxy.FROZEN_ROLE(),
          wallets[1].address,
        );

        expect(isFrozen).to.equal(true);
      });

      it("✨ transfer should fail when frozen", async () => {
        const { tokenProxy, deployer, riskManager, wallets } =
          await loadFixture(deployFixture);

        const amount = ethers.parseEther("10");
        await mint(tokenProxy, deployer, wallets[0].address, amount);
        await mint(tokenProxy, deployer, wallets[1].address, amount);

        await grantRole(
          tokenProxy,
          await tokenProxy.RISK_MANAGER_ROLE(),
          riskManager.address,
        );

        const freezeTx = await tokenProxy
          .connect(riskManager)
          .freeze(wallets[0].address);
        await freezeTx.wait();

        // Both sender and receiver should be restricted when frozen
        await expect(
          tokenProxy.connect(wallets[0]).transfer(wallets[1].address, amount),
        ).to.be.revertedWithCustomError(tokenProxy, "AccountFrozen");

        await expect(
          tokenProxy.connect(wallets[1]).transfer(wallets[0].address, amount),
        ).to.be.revertedWithCustomError(tokenProxy, "AccountFrozen");
      });

      it("✨ transferFrom should fail when frozen", async () => {
        const { tokenProxy, deployer, riskManager, wallets } =
          await loadFixture(deployFixture);

        const amount = ethers.parseEther("10");
        await mint(tokenProxy, deployer, wallets[0].address, amount);
        await mint(tokenProxy, deployer, wallets[1].address, amount);

        const approveTx = await tokenProxy
          .connect(wallets[0])
          .approve(wallets[1].address, amount);
        await approveTx.wait();
        const approveTx2 = await tokenProxy
          .connect(wallets[1])
          .approve(wallets[0].address, amount);
        await approveTx2.wait();

        expect(
          await tokenProxy.allowance(wallets[0].address, wallets[1].address),
        ).to.equal(amount);
        expect(
          await tokenProxy.allowance(wallets[1].address, wallets[0].address),
        ).to.equal(amount);

        await grantRole(
          tokenProxy,
          await tokenProxy.RISK_MANAGER_ROLE(),
          riskManager.address,
        );

        const freezeTx = await tokenProxy
          .connect(riskManager)
          .freeze(wallets[0].address);
        await freezeTx.wait();

        // Both sender and receiver should be restricted when frozen
        await expect(
          tokenProxy
            .connect(wallets[1])
            .transferFrom(
              wallets[0].address,
              wallets[1].address,
              ethers.parseEther("1"),
            ),
        ).to.be.revertedWithCustomError(tokenProxy, "AccountFrozen");
        await expect(
          tokenProxy
            .connect(wallets[0])
            .transferFrom(
              wallets[1].address,
              wallets[0].address,
              ethers.parseEther("1"),
            ),
        ).to.be.revertedWithCustomError(tokenProxy, "AccountFrozen");
      });

      it("✨ approve should fail when frozen", async () => {
        const { tokenProxy, deployer, riskManager, wallets } =
          await loadFixture(deployFixture);

        const amount = ethers.parseEther("10");

        await grantRole(
          tokenProxy,
          await tokenProxy.RISK_MANAGER_ROLE(),
          riskManager.address,
        );

        const freezeTx = await tokenProxy
          .connect(riskManager)
          .freeze(wallets[0].address);
        await freezeTx.wait();

        await expect(
          tokenProxy.connect(wallets[0]).approve(wallets[1].address, amount),
        ).to.be.revertedWithCustomError(tokenProxy, "AccountFrozen");
        await expect(
          tokenProxy.connect(wallets[1]).approve(wallets[0].address, amount),
        ).to.be.revertedWithCustomError(tokenProxy, "AccountFrozen");
      });

      it("✨ revoke allowance is available even when frozen", async () => {
        const { tokenProxy, deployer, riskManager, wallets } =
          await loadFixture(deployFixture);

        const amount = ethers.parseEther("10");

        const approveTx = await tokenProxy
          .connect(wallets[0])
          .approve(wallets[1].address, amount);
        await approveTx.wait();

        expect(
          await tokenProxy.allowance(wallets[0].address, wallets[1].address),
        ).to.equal(amount);

        await grantRole(
          tokenProxy,
          await tokenProxy.RISK_MANAGER_ROLE(),
          riskManager.address,
        );

        const freezeTx = await tokenProxy
          .connect(riskManager)
          .freeze(wallets[0].address);
        await freezeTx.wait();

        const revokeTx = await tokenProxy
          .connect(wallets[0])
          .approve(wallets[1].address, 0);
        await revokeTx.wait();

        const allowanceAfter = await tokenProxy.allowance(
          wallets[0].address,
          wallets[1].address,
        );
        expect(allowanceAfter).to.equal(0);
      });

      it("✨ only RISK_MANAGER_ROLE can call unfreeze()", async () => {
        const { tokenProxy, deployer, riskManager, wallets } =
          await loadFixture(deployFixture);

        await grantRole(
          tokenProxy,
          await tokenProxy.RISK_MANAGER_ROLE(),
          riskManager.address,
        );

        const freezeTx = await tokenProxy
          .connect(riskManager)
          .freeze(wallets[0].address);
        await freezeTx.wait();

        expect(
          await tokenProxy.hasRole(
            await tokenProxy.FROZEN_ROLE(),
            wallets[0].address,
          ),
        ).to.equal(true);

        await expect(
          tokenProxy.connect(wallets[1]).unfreeze(wallets[0].address),
        ).to.be.revertedWithCustomError(
          tokenProxy,
          "AccessControlUnauthorizedAccount",
        );

        const unfreezeTx = await tokenProxy
          .connect(riskManager)
          .unfreeze(wallets[0].address);
        await unfreezeTx.wait();

        const isFrozenAfter = await tokenProxy.hasRole(
          await tokenProxy.FROZEN_ROLE(),
          wallets[0].address,
        );

        expect(isFrozenAfter).to.equal(false);
      });
      it("✨ transfer should succeed after unfrozen", async () => {
        const { tokenProxy, deployer, riskManager, wallets } =
          await loadFixture(deployFixture);

        const amount = ethers.parseEther("10");
        await mint(tokenProxy, deployer, wallets[0].address, amount);

        await grantRole(
          tokenProxy,
          await tokenProxy.RISK_MANAGER_ROLE(),
          riskManager.address,
        );

        const freezeTx = await tokenProxy
          .connect(riskManager)
          .freeze(wallets[0].address);
        await freezeTx.wait();

        expect(
          await tokenProxy.hasRole(
            await tokenProxy.FROZEN_ROLE(),
            wallets[0].address,
          ),
        ).to.equal(true);

        const unfreezeTx = await tokenProxy
          .connect(riskManager)
          .unfreeze(wallets[0].address);
        await unfreezeTx.wait();

        expect(
          await tokenProxy.hasRole(
            await tokenProxy.FROZEN_ROLE(),
            wallets[0].address,
          ),
        ).to.equal(false);

        const w1BalBefore = await tokenProxy.balanceOf(wallets[1].address);

        const transferAmount = ethers.parseEther("1");
        const transferTx = await tokenProxy
          .connect(wallets[0])
          .transfer(wallets[1].address, transferAmount);
        await transferTx.wait();

        const w1BalAfter = await tokenProxy.balanceOf(wallets[1].address);
        expect(w1BalAfter - w1BalBefore).to.equal(transferAmount);
      });
      it("✨ transferFrom should succeed after unfrozen", async () => {
        const { tokenProxy, deployer, riskManager, wallets } =
          await loadFixture(deployFixture);

        const amount = ethers.parseEther("10");
        await mint(tokenProxy, deployer, wallets[0].address, amount);

        await grantRole(
          tokenProxy,
          await tokenProxy.RISK_MANAGER_ROLE(),
          riskManager.address,
        );

        const freezeTx = await tokenProxy
          .connect(riskManager)
          .freeze(wallets[0].address);
        await freezeTx.wait();

        expect(
          await tokenProxy.hasRole(
            await tokenProxy.FROZEN_ROLE(),
            wallets[0].address,
          ),
        ).to.equal(true);

        const unfreezeTx = await tokenProxy
          .connect(riskManager)
          .unfreeze(wallets[0].address);
        await unfreezeTx.wait();

        expect(
          await tokenProxy.hasRole(
            await tokenProxy.FROZEN_ROLE(),
            wallets[0].address,
          ),
        ).to.equal(false);

        const w1BalBefore = await tokenProxy.balanceOf(wallets[1].address);

        const transferAmount = ethers.parseEther("1");

        const approveTx = await tokenProxy
          .connect(wallets[0])
          .approve(wallets[1].address, transferAmount);
        await approveTx.wait();

        const transferFromTx = await tokenProxy
          .connect(wallets[1])
          .transferFrom(wallets[0].address, wallets[1].address, transferAmount);
        await transferFromTx.wait();

        const w1BalAfter = await tokenProxy.balanceOf(wallets[1].address);
        expect(w1BalAfter - w1BalBefore).to.equal(transferAmount);
      });

      it("✨ approve should succeed after unfrozen", async () => {
        const { tokenProxy, deployer, riskManager, wallets } =
          await loadFixture(deployFixture);

        const amount = ethers.parseEther("10");

        await grantRole(
          tokenProxy,
          await tokenProxy.RISK_MANAGER_ROLE(),
          riskManager.address,
        );

        const freezeTx = await tokenProxy
          .connect(riskManager)
          .freeze(wallets[0].address);
        await freezeTx.wait();
        expect(
          await tokenProxy.hasRole(
            await tokenProxy.FROZEN_ROLE(),
            wallets[0].address,
          ),
        ).to.equal(true);

        const unfreezeTx = await tokenProxy
          .connect(riskManager)
          .unfreeze(wallets[0].address);
        await unfreezeTx.wait();
        expect(
          await tokenProxy.hasRole(
            await tokenProxy.FROZEN_ROLE(),
            wallets[0].address,
          ),
        ).to.equal(false);

        const approveTx = await tokenProxy
          .connect(wallets[0])
          .approve(wallets[1].address, amount * 2n);
        await approveTx.wait();

        const allowanceAfter = await tokenProxy.allowance(
          wallets[0].address,
          wallets[1].address,
        );

        expect(allowanceAfter).to.equal(amount * 2n);
      });
    });
    describe("SelfFreeze", () => {
      it("✨ Anyone can call selfFreeze()", async () => {
        const { tokenProxy, wallets } = await loadFixture(deployFixture);

        expect(
          await tokenProxy.hasRole(
            await tokenProxy.FROZEN_ROLE(),
            wallets[0].address,
          ),
        ).to.equal(false);

        const selfFreezeTx = await tokenProxy.connect(wallets[0]).selfFreeze();
        await selfFreezeTx.wait();

        expect(
          await tokenProxy.hasRole(
            await tokenProxy.FROZEN_ROLE(),
            wallets[0].address,
          ),
        ).to.equal(true);
      });
    });
    describe("wipeFrozenAccount", () => {
      it("✨ only RISK_MANAGER_ROLE can call wipeFrozenAccount()", async () => {
        const { tokenProxy, deployer, riskManager, wallets } =
          await loadFixture(deployFixture);

        await mint(
          tokenProxy,
          deployer,
          wallets[0].address,
          ethers.parseEther("10"),
        );

        await grantRole(
          tokenProxy,
          await tokenProxy.RISK_MANAGER_ROLE(),
          riskManager.address,
        );

        const freezeTx = await tokenProxy
          .connect(riskManager)
          .freeze(wallets[0].address);
        await freezeTx.wait();

        // no role account should be rejected
        await expect(
          tokenProxy.connect(wallets[1]).wipeFrozenAccount(wallets[0].address),
        ).to.be.revertedWithCustomError(
          tokenProxy,
          "AccessControlUnauthorizedAccount",
        );

        const wipeTx = await tokenProxy
          .connect(riskManager)
          .wipeFrozenAccount(wallets[0].address);
        await wipeTx.wait();

        const w0Bal = await tokenProxy.balanceOf(wallets[0].address);
        expect(w0Bal).to.equal(0);
      });
      it("✨ only frozen accounts can be wiped", async () => {
        const { tokenProxy, deployer, riskManager, wallets } =
          await loadFixture(deployFixture);

        await mint(
          tokenProxy,
          deployer,
          wallets[0].address,
          ethers.parseEther("10"),
        );

        await grantRole(
          tokenProxy,
          await tokenProxy.RISK_MANAGER_ROLE(),
          riskManager.address,
        );

        const freezeTx = await tokenProxy
          .connect(riskManager)
          .freeze(wallets[0].address);
        await freezeTx.wait();

        await expect(
          tokenProxy.connect(riskManager).wipeFrozenAccount(wallets[1].address),
        ).to.be.revertedWithCustomError(tokenProxy, "AccountNotFrozen");

        const wipeTx = await tokenProxy
          .connect(riskManager)
          .wipeFrozenAccount(wallets[0].address);
        await wipeTx.wait();

        const w0Bal = await tokenProxy.balanceOf(wallets[0].address);
        expect(w0Bal).to.equal(0);
      });
      it("✨ should wipe the balance of a frozen account", async () => {
        const { tokenProxy, deployer, riskManager, wallets } =
          await loadFixture(deployFixture);

        const mintAmount = ethers.parseEther("10");
        await mint(tokenProxy, deployer, wallets[0].address, mintAmount);

        expect(await tokenProxy.balanceOf(wallets[0].address)).to.equal(
          mintAmount,
        );

        await grantRole(
          tokenProxy,
          await tokenProxy.RISK_MANAGER_ROLE(),
          riskManager.address,
        );

        const freezeTx = await tokenProxy
          .connect(riskManager)
          .freeze(wallets[0].address);
        await freezeTx.wait();

        await expect(
          tokenProxy.connect(riskManager).wipeFrozenAccount(wallets[1].address),
        ).to.be.revertedWithCustomError(tokenProxy, "AccountNotFrozen");

        const wipeTx = await tokenProxy
          .connect(riskManager)
          .wipeFrozenAccount(wallets[0].address);
        await wipeTx.wait();

        const w0Bal = await tokenProxy.balanceOf(wallets[0].address);
        expect(w0Bal).to.equal(0);
      });
      it("✨ allowances should be reset after wiping a frozen account", async () => {
        const { tokenProxy, deployer, riskManager, wallets } =
          await loadFixture(deployFixture);

        await grantRole(
          tokenProxy,
          await tokenProxy.RISK_MANAGER_ROLE(),
          riskManager,
        );

        const amount = ethers.parseEther("10");

        const approveTx = await approve(
          tokenProxy,
          wallets[0],
          wallets[1].address,
          amount,
        );

        const allwanceBefore = await tokenProxy.allowance(
          wallets[0].address,
          wallets[1].address,
        );

        const freezeTx = await tokenProxy
          .connect(riskManager)
          .freeze(wallets[0].address);
        await freezeTx.wait();

        const wipeTx = await tokenProxy
          .connect(riskManager)
          .wipeFrozenAccount(wallets[0].address);
        await wipeTx.wait();

        const allwanceAfter = await tokenProxy.allowance(
          wallets[0].address,
          wallets[1].address,
        );

        expect(allwanceBefore).to.equal(amount);
        expect(allwanceAfter).to.equal(0);
      });
    });
  });
  describe("Authorization / Signature", () => {
    describe("mintWithAuthorization", () => {
      it("✨ mint should succeed with valid authorization", async () => {
        const { tokenProxy, deployer, mintApprover, vaultMinter, wallets } =
          await loadFixture(deployFixture);

        await grantRole(
          tokenProxy,
          await tokenProxy.MINT_APPROVER_ROLE(),
          mintApprover.address,
        );
        await grantRole(
          tokenProxy,
          await tokenProxy.VAULT_MINTER_ROLE(),
          vaultMinter.address,
        );
        expect(
          await tokenProxy.hasRole(
            await tokenProxy.MINT_APPROVER_ROLE(),
            mintApprover.address,
          ),
        ).to.equal(true);
        expect(
          await tokenProxy.hasRole(
            await tokenProxy.VAULT_MINTER_ROLE(),
            vaultMinter.address,
          ),
        ).to.equal(true);

        const amount = ethers.parseEther("10");
        const chainId = (await ethers.provider.getNetwork()).chainId;

        const name = await tokenProxy.name();

        const domain = {
          name: name,
          version: "1",
          chainId: chainId,
          verifyingContract: tokenProxy.target,
        };

        const typeHash = {
          MintWithAuthorization: [
            { name: "to", type: "address" },
            { name: "amount", type: "uint256" },
            { name: "nonce", type: "bytes32" },
            { name: "validAfter", type: "uint256" },
            { name: "validBefore", type: "uint256" },
          ],
        };

        const message = {
          to: wallets[0].address,
          amount: amount.toString(),
          nonce: ethers.randomBytes(32),
          validAfter: Math.floor(Date.now() / 1000), // valid from now
          validBefore: Math.floor(Date.now() / 1000) + 3600, // valid for 1 hour
        };

        const signature = await mintApprover.signTypedData(
          domain,
          typeHash,
          message,
        );

        const { v, r, s } = ethers.Signature.from(signature);

        const w1BalBefore = await tokenProxy.balanceOf(wallets[0].address);

        const mintTx = await tokenProxy
          .connect(vaultMinter)
          .mintWithAuthorization(
            message.to,
            message.amount,
            message.nonce,
            message.validAfter,
            message.validBefore,
            v,
            r,
            s,
          );
        await mintTx.wait();

        const w1BalAfter = await tokenProxy.balanceOf(wallets[0].address);
        expect(w1BalAfter - w1BalBefore).to.equal(amount);
      });
      it("✨ mint should fail with invalid authorization : unauthorized signer", async () => {
        const { tokenProxy, deployer, mintApprover, vaultMinter, wallets } =
          await loadFixture(deployFixture);

        await grantRole(
          tokenProxy,
          await tokenProxy.MINT_APPROVER_ROLE(),
          mintApprover.address,
        );
        await grantRole(
          tokenProxy,
          await tokenProxy.VAULT_MINTER_ROLE(),
          vaultMinter.address,
        );
        expect(
          await tokenProxy.hasRole(
            await tokenProxy.MINT_APPROVER_ROLE(),
            mintApprover.address,
          ),
        ).to.equal(true);
        expect(
          await tokenProxy.hasRole(
            await tokenProxy.VAULT_MINTER_ROLE(),
            vaultMinter.address,
          ),
        ).to.equal(true);

        const amount = ethers.parseEther("10");
        const chainId = (await ethers.provider.getNetwork()).chainId;

        const name = await tokenProxy.name();

        const domain = {
          name: name,
          version: "1",
          chainId: chainId,
          verifyingContract: tokenProxy.target,
        };

        const typeHash = {
          MintWithAuthorization: [
            { name: "to", type: "address" },
            { name: "amount", type: "uint256" },
            { name: "nonce", type: "bytes32" },
            { name: "validAfter", type: "uint256" },
            { name: "validBefore", type: "uint256" },
          ],
        };

        const message = {
          to: wallets[0].address,
          amount: amount.toString(),
          nonce: ethers.randomBytes(32),
          validAfter: Math.floor(Date.now() / 1000), // valid from now
          validBefore: Math.floor(Date.now() / 1000) + 3600, // valid for 1 hour
        };

        const signature = await wallets[0].signTypedData(
          domain,
          typeHash,
          message,
        );

        const { v, r, s } = ethers.Signature.from(signature);

        await expect(
          tokenProxy
            .connect(vaultMinter)
            .mintWithAuthorization(
              message.to,
              message.amount,
              message.nonce,
              message.validAfter,
              message.validBefore,
              v,
              r,
              s,
            ),
        ).to.be.revertedWithCustomError(tokenProxy, "InvalidSignature");
      });
      it("✨ mint should fail with invalid authorization : expired authorization", async () => {
        const { tokenProxy, deployer, mintApprover, vaultMinter, wallets } =
          await loadFixture(deployFixture);

        await grantRole(
          tokenProxy,
          await tokenProxy.MINT_APPROVER_ROLE(),
          mintApprover.address,
        );
        await grantRole(
          tokenProxy,
          await tokenProxy.VAULT_MINTER_ROLE(),
          vaultMinter.address,
        );
        expect(
          await tokenProxy.hasRole(
            await tokenProxy.MINT_APPROVER_ROLE(),
            mintApprover.address,
          ),
        ).to.equal(true);
        expect(
          await tokenProxy.hasRole(
            await tokenProxy.VAULT_MINTER_ROLE(),
            vaultMinter.address,
          ),
        ).to.equal(true);

        const amount = ethers.parseEther("10");
        const chainId = (await ethers.provider.getNetwork()).chainId;

        const name = await tokenProxy.name();

        const domain = {
          name: name,
          version: "1",
          chainId: chainId,
          verifyingContract: tokenProxy.target,
        };

        const typeHash = {
          MintWithAuthorization: [
            { name: "to", type: "address" },
            { name: "amount", type: "uint256" },
            { name: "nonce", type: "bytes32" },
            { name: "validAfter", type: "uint256" },
            { name: "validBefore", type: "uint256" },
          ],
        };

        const message = {
          to: wallets[0].address,
          amount: amount.toString(),
          nonce: ethers.randomBytes(32),
          validAfter: Math.floor(Date.now() / 1000) - 3600, // valid from now
          validBefore: Math.floor(Date.now() / 1000) - 1800, // valid for 1 hour
        };

        const signature = await wallets[0].signTypedData(
          domain,
          typeHash,
          message,
        );

        const { v, r, s } = ethers.Signature.from(signature);

        await expect(
          tokenProxy
            .connect(vaultMinter)
            .mintWithAuthorization(
              message.to,
              message.amount,
              message.nonce,
              message.validAfter,
              message.validBefore,
              v,
              r,
              s,
            ),
        ).to.be.revertedWithCustomError(tokenProxy, "AuthorizationExpired");
      });
      it("✨ mint should fail with invalid authorization : used nonce", async () => {
        const { tokenProxy, deployer, mintApprover, vaultMinter, wallets } =
          await loadFixture(deployFixture);

        await grantRole(
          tokenProxy,
          await tokenProxy.MINT_APPROVER_ROLE(),
          mintApprover.address,
        );
        await grantRole(
          tokenProxy,
          await tokenProxy.VAULT_MINTER_ROLE(),
          vaultMinter.address,
        );
        expect(
          await tokenProxy.hasRole(
            await tokenProxy.MINT_APPROVER_ROLE(),
            mintApprover.address,
          ),
        ).to.equal(true);
        expect(
          await tokenProxy.hasRole(
            await tokenProxy.VAULT_MINTER_ROLE(),
            vaultMinter.address,
          ),
        ).to.equal(true);

        const amount = ethers.parseEther("10");
        const chainId = (await ethers.provider.getNetwork()).chainId;

        const name = await tokenProxy.name();

        const domain = {
          name: name,
          version: "1",
          chainId: chainId,
          verifyingContract: tokenProxy.target,
        };

        const typeHash = {
          MintWithAuthorization: [
            { name: "to", type: "address" },
            { name: "amount", type: "uint256" },
            { name: "nonce", type: "bytes32" },
            { name: "validAfter", type: "uint256" },
            { name: "validBefore", type: "uint256" },
          ],
        };

        const message = {
          to: wallets[0].address,
          amount: amount.toString(),
          nonce: ethers.randomBytes(32),
          validAfter: Math.floor(Date.now() / 1000), // valid from now
          validBefore: Math.floor(Date.now() / 1000) + 3600, // valid for 1 hour
        };

        const signature = await mintApprover.signTypedData(
          domain,
          typeHash,
          message,
        );

        const { v, r, s } = ethers.Signature.from(signature);

        const transferTx = await tokenProxy
          .connect(vaultMinter)
          .mintWithAuthorization(
            message.to,
            message.amount,
            message.nonce,
            message.validAfter,
            message.validBefore,
            v,
            r,
            s,
          );
        await transferTx.wait();

        await expect(
          tokenProxy
            .connect(vaultMinter)
            .mintWithAuthorization(
              message.to,
              message.amount,
              message.nonce,
              message.validAfter,
              message.validBefore,
              v,
              r,
              s,
            ),
        ).to.be.revertedWithCustomError(tokenProxy, "InvalidAuthorization");
      });
    });
    describe("transferWithAuthorization", () => {
      it("✨ transfer should succeed with valid authorization", async () => {
        const { tokenProxy, deployer, wallets } = await loadFixture(
          deployFixture,
        );

        await mint(
          tokenProxy,
          deployer,
          wallets[0].address,
          ethers.parseEther("10"),
        );

        const amount = ethers.parseEther("1");
        const chainId = (await ethers.provider.getNetwork()).chainId;

        const name = await tokenProxy.name();

        const domain = {
          name: name,
          version: "1",
          chainId: chainId,
          verifyingContract: tokenProxy.target,
        };

        const typeHash = {
          TransferWithAuthorization: [
            { name: "from", type: "address" },
            { name: "to", type: "address" },
            { name: "value", type: "uint256" },
            { name: "validAfter", type: "uint256" },
            { name: "validBefore", type: "uint256" },
            { name: "nonce", type: "bytes32" },
          ],
        };

        const message = {
          from: wallets[0].address,
          to: wallets[1].address,
          value: amount.toString(),
          nonce: ethers.randomBytes(32),
          validAfter: Math.floor(Date.now() / 1000), // valid from now
          validBefore: Math.floor(Date.now() / 1000) + 3600, // valid for 1 hour
        };

        const signature = await wallets[0].signTypedData(
          domain,
          typeHash,
          message,
        );

        const { v, r, s } = ethers.Signature.from(signature);

        const w1BalBefore = await tokenProxy.balanceOf(wallets[1].address);

        const transferTx = await tokenProxy
          .connect(wallets[2])
          .transferWithAuthorization(
            message.from,
            message.to,
            message.value,
            message.validAfter,
            message.validBefore,
            message.nonce,
            v,
            r,
            s,
          );
        await transferTx.wait();

        const w1BalAfter = await tokenProxy.balanceOf(wallets[1].address);
        expect(w1BalAfter - w1BalBefore).to.equal(amount);
      });

      it("✨ transfer should fail with invalid authorization : expired authorization", async () => {
        const { tokenProxy, deployer, wallets } = await loadFixture(
          deployFixture,
        );

        await mint(
          tokenProxy,
          deployer,
          wallets[0].address,
          ethers.parseEther("10"),
        );

        const amount = ethers.parseEther("1");
        const chainId = (await ethers.provider.getNetwork()).chainId;

        const name = await tokenProxy.name();

        const domain = {
          name: name,
          version: "1",
          chainId: chainId,
          verifyingContract: tokenProxy.target,
        };

        const typeHash = {
          TransferWithAuthorization: [
            { name: "from", type: "address" },
            { name: "to", type: "address" },
            { name: "value", type: "uint256" },
            { name: "validAfter", type: "uint256" },
            { name: "validBefore", type: "uint256" },
            { name: "nonce", type: "bytes32" },
          ],
        };

        const message = {
          from: wallets[0].address,
          to: wallets[1].address,
          value: amount.toString(),
          nonce: ethers.randomBytes(32),
          validAfter: Math.floor(Date.now() / 1000) - 3600,
          validBefore: Math.floor(Date.now() / 1000) - 1800, // expired 30 minutes ago
        };

        const signature = await wallets[0].signTypedData(
          domain,
          typeHash,
          message,
        );

        const { v, r, s } = ethers.Signature.from(signature);

        const w1BalBefore = await tokenProxy.balanceOf(wallets[1].address);

        await expect(
          tokenProxy
            .connect(wallets[2])
            .transferWithAuthorization(
              message.from,
              message.to,
              message.value,
              message.validAfter,
              message.validBefore,
              message.nonce,
              v,
              r,
              s,
            ),
        ).to.be.revertedWithCustomError(tokenProxy, "AuthorizationExpired");
      });
      it("✨ transfer should fail with invalid authorization : used nonce", async () => {
        const { tokenProxy, deployer, wallets } = await loadFixture(
          deployFixture,
        );

        await mint(
          tokenProxy,
          deployer,
          wallets[0].address,
          ethers.parseEther("10"),
        );

        const amount = ethers.parseEther("1");
        const chainId = (await ethers.provider.getNetwork()).chainId;

        const name = await tokenProxy.name();

        const domain = {
          name: name,
          version: "1",
          chainId: chainId,
          verifyingContract: tokenProxy.target,
        };

        const typeHash = {
          TransferWithAuthorization: [
            { name: "from", type: "address" },
            { name: "to", type: "address" },
            { name: "value", type: "uint256" },
            { name: "validAfter", type: "uint256" },
            { name: "validBefore", type: "uint256" },
            { name: "nonce", type: "bytes32" },
          ],
        };

        const message = {
          from: wallets[0].address,
          to: wallets[1].address,
          value: amount.toString(),
          nonce: ethers.randomBytes(32),
          validAfter: Math.floor(Date.now() / 1000), // valid from now
          validBefore: Math.floor(Date.now() / 1000) + 3600, // valid for 1 hour
        };

        const signature = await wallets[0].signTypedData(
          domain,
          typeHash,
          message,
        );

        const { v, r, s } = ethers.Signature.from(signature);

        const w1BalBefore = await tokenProxy.balanceOf(wallets[1].address);

        const transferTx = await tokenProxy
          .connect(wallets[2])
          .transferWithAuthorization(
            message.from,
            message.to,
            message.value,
            message.validAfter,
            message.validBefore,
            message.nonce,
            v,
            r,
            s,
          );
        await transferTx.wait();

        const w1BalAfter = await tokenProxy.balanceOf(wallets[1].address);
        expect(w1BalAfter - w1BalBefore).to.equal(amount);

        await expect(
          tokenProxy
            .connect(wallets[2])
            .transferWithAuthorization(
              message.from,
              message.to,
              message.value,
              message.validAfter,
              message.validBefore,
              message.nonce,
              v,
              r,
              s,
            ),
        ).to.be.revertedWithCustomError(tokenProxy, "InvalidAuthorization");
      });
    });
    describe("receiveWithAuthorization", () => {
      it("✨ receive should succeed with valid authorization", async () => {
        const { tokenProxy, deployer, wallets } = await loadFixture(
          deployFixture,
        );

        await mint(
          tokenProxy,
          deployer,
          wallets[0].address,
          ethers.parseEther("10"),
        );

        const amount = ethers.parseEther("1");
        const chainId = (await ethers.provider.getNetwork()).chainId;

        const name = await tokenProxy.name();

        const domain = {
          name: name,
          version: "1",
          chainId: chainId,
          verifyingContract: tokenProxy.target,
        };

        const typeHash = {
          ReceiveWithAuthorization: [
            { name: "from", type: "address" },
            { name: "to", type: "address" },
            { name: "value", type: "uint256" },
            { name: "validAfter", type: "uint256" },
            { name: "validBefore", type: "uint256" },
            { name: "nonce", type: "bytes32" },
          ],
        };

        const message = {
          from: wallets[0].address,
          to: wallets[1].address,
          value: amount.toString(),
          nonce: ethers.randomBytes(32),
          validAfter: Math.floor(Date.now() / 1000), // valid from now
          validBefore: Math.floor(Date.now() / 1000) + 3600, // valid for 1 hour
        };

        const signature = await wallets[0].signTypedData(
          domain,
          typeHash,
          message,
        );

        const { v, r, s } = ethers.Signature.from(signature);

        const w1BalBefore = await tokenProxy.balanceOf(wallets[1].address);

        const receiveTx = await tokenProxy
          .connect(wallets[1])
          .receiveWithAuthorization(
            message.from,
            message.to,
            message.value,
            message.validAfter,
            message.validBefore,
            message.nonce,
            v,
            r,
            s,
          );
        await receiveTx.wait();

        const w1BalAfter = await tokenProxy.balanceOf(wallets[1].address);
        expect(w1BalAfter - w1BalBefore).to.equal(amount);
      });
      it("✨ receive should fail with invalid authorization : expired authorization", async () => {
        const { tokenProxy, deployer, wallets } = await loadFixture(
          deployFixture,
        );

        await mint(
          tokenProxy,
          deployer,
          wallets[0].address,
          ethers.parseEther("10"),
        );

        const amount = ethers.parseEther("1");
        const chainId = (await ethers.provider.getNetwork()).chainId;

        const name = await tokenProxy.name();

        const domain = {
          name: name,
          version: "1",
          chainId: chainId,
          verifyingContract: tokenProxy.target,
        };

        const typeHash = {
          ReceiveWithAuthorization: [
            { name: "from", type: "address" },
            { name: "to", type: "address" },
            { name: "value", type: "uint256" },
            { name: "validAfter", type: "uint256" },
            { name: "validBefore", type: "uint256" },
            { name: "nonce", type: "bytes32" },
          ],
        };

        const message = {
          from: wallets[0].address,
          to: wallets[1].address,
          value: amount.toString(),
          nonce: ethers.randomBytes(32),
          validAfter: Math.floor(Date.now() / 1000) - 3600,
          validBefore: Math.floor(Date.now() / 1000) - 1800,
        };

        const signature = await wallets[0].signTypedData(
          domain,
          typeHash,
          message,
        );

        const { v, r, s } = ethers.Signature.from(signature);

        const w1BalBefore = await tokenProxy.balanceOf(wallets[1].address);

        await expect(
          tokenProxy
            .connect(wallets[1])
            .receiveWithAuthorization(
              message.from,
              message.to,
              message.value,
              message.validAfter,
              message.validBefore,
              message.nonce,
              v,
              r,
              s,
            ),
        ).to.be.revertedWithCustomError(tokenProxy, "AuthorizationExpired");
      });
      it("✨ receive should fail with invalid authorization : used nonce", async () => {
        const { tokenProxy, deployer, wallets } = await loadFixture(
          deployFixture,
        );

        await mint(
          tokenProxy,
          deployer,
          wallets[0].address,
          ethers.parseEther("10"),
        );

        const amount = ethers.parseEther("1");
        const chainId = (await ethers.provider.getNetwork()).chainId;

        const name = await tokenProxy.name();

        const domain = {
          name: name,
          version: "1",
          chainId: chainId,
          verifyingContract: tokenProxy.target,
        };

        const typeHash = {
          ReceiveWithAuthorization: [
            { name: "from", type: "address" },
            { name: "to", type: "address" },
            { name: "value", type: "uint256" },
            { name: "validAfter", type: "uint256" },
            { name: "validBefore", type: "uint256" },
            { name: "nonce", type: "bytes32" },
          ],
        };

        const message = {
          from: wallets[0].address,
          to: wallets[1].address,
          value: amount.toString(),
          nonce: ethers.randomBytes(32),
          validAfter: Math.floor(Date.now() / 1000),
          validBefore: Math.floor(Date.now() / 1000) + 1800,
        };

        const signature = await wallets[0].signTypedData(
          domain,
          typeHash,
          message,
        );

        const { v, r, s } = ethers.Signature.from(signature);

        const w1BalBefore = await tokenProxy.balanceOf(wallets[1].address);

        const receiveTx = await tokenProxy
          .connect(wallets[1])
          .receiveWithAuthorization(
            message.from,
            message.to,
            message.value,
            message.validAfter,
            message.validBefore,
            message.nonce,
            v,
            r,
            s,
          );
        await receiveTx.wait();

        await expect(
          tokenProxy
            .connect(wallets[1])
            .receiveWithAuthorization(
              message.from,
              message.to,
              message.value,
              message.validAfter,
              message.validBefore,
              message.nonce,
              v,
              r,
              s,
            ),
        ).to.be.revertedWithCustomError(tokenProxy, "InvalidAuthorization");
      });
      it("✨ receive should fail when caller is not recipient", async () => {
        const { tokenProxy, deployer, wallets } = await loadFixture(
          deployFixture,
        );

        await mint(
          tokenProxy,
          deployer,
          wallets[0].address,
          ethers.parseEther("10"),
        );

        const amount = ethers.parseEther("1");
        const chainId = (await ethers.provider.getNetwork()).chainId;

        const name = await tokenProxy.name();

        const domain = {
          name: name,
          version: "1",
          chainId: chainId,
          verifyingContract: tokenProxy.target,
        };

        const typeHash = {
          ReceiveWithAuthorization: [
            { name: "from", type: "address" },
            { name: "to", type: "address" },
            { name: "value", type: "uint256" },
            { name: "validAfter", type: "uint256" },
            { name: "validBefore", type: "uint256" },
            { name: "nonce", type: "bytes32" },
          ],
        };

        const message = {
          from: wallets[0].address,
          to: wallets[1].address,
          value: amount.toString(),
          nonce: ethers.randomBytes(32),
          validAfter: Math.floor(Date.now() / 1000),
          validBefore: Math.floor(Date.now() / 1000) + 1800,
        };

        const signature = await wallets[0].signTypedData(
          domain,
          typeHash,
          message,
        );

        const { v, r, s } = ethers.Signature.from(signature);

        const w1BalBefore = await tokenProxy.balanceOf(wallets[1].address);

        await expect(
          tokenProxy
            .connect(wallets[2])
            .receiveWithAuthorization(
              message.from,
              message.to,
              message.value,
              message.validAfter,
              message.validBefore,
              message.nonce,
              v,
              r,
              s,
            ),
        ).to.be.revertedWithCustomError(tokenProxy, "CallerIsNotRecipient");
      });
    });
    describe("cancelAuthorization", () => {
      it("✨ mint tx with cancelled authorization should fail", async () => {
        const { tokenProxy, deployer, mintApprover, vaultMinter, wallets } =
          await loadFixture(deployFixture);
        await grantRole(
          tokenProxy,
          await tokenProxy.MINT_APPROVER_ROLE(),
          mintApprover.address,
        );
        await grantRole(
          tokenProxy,
          await tokenProxy.VAULT_MINTER_ROLE(),
          vaultMinter.address,
        );

        const amount = ethers.parseEther("10");
        const chainId = (await ethers.provider.getNetwork()).chainId;

        const name = await tokenProxy.name();

        const domain = {
          name: name,
          version: "1",
          chainId: chainId,
          verifyingContract: tokenProxy.target,
        };

        const typeHash = {
          MintWithAuthorization: [
            { name: "to", type: "address" },
            { name: "amount", type: "uint256" },
            { name: "nonce", type: "bytes32" },
            { name: "validAfter", type: "uint256" },
            { name: "validBefore", type: "uint256" },
          ],
        };

        const message = {
          to: wallets[0].address,
          amount: amount.toString(),
          nonce: ethers.randomBytes(32),
          validAfter: Math.floor(Date.now() / 1000), // valid from now
          validBefore: Math.floor(Date.now() / 1000) + 3600, // valid for 1 hour
        };

        const signature = await mintApprover.signTypedData(
          domain,
          typeHash,
          message,
        );

        const { v, r, s } = ethers.Signature.from(signature);

        const cancelTypedData = {
          CancelAuthorization: [
            { name: "authorizer", type: "address" },
            { name: "nonce", type: "bytes32" },
          ],
        };

        const cancelMessage = {
          authorizer: mintApprover.address,
          nonce: message.nonce,
        };

        const cancelSignature = await mintApprover.signTypedData(
          domain,
          cancelTypedData,
          cancelMessage,
        );

        const { v: cv, r: cr, s: cs } = ethers.Signature.from(cancelSignature);

        const cancelTx = await tokenProxy
          .connect(mintApprover)
          .cancelAuthorization(mintApprover.address, message.nonce, cv, cr, cs);
        await cancelTx.wait();

        await expect(
          tokenProxy
            .connect(vaultMinter)
            .mintWithAuthorization(
              message.to,
              message.amount,
              message.nonce,
              message.validAfter,
              message.validBefore,
              v,
              r,
              s,
            ),
        ).to.be.revertedWithCustomError(tokenProxy, "InvalidAuthorization");
      });
      it("✨ transfer tx with cancelled authorization should fail", async () => {
        const { tokenProxy, deployer, wallets } = await loadFixture(
          deployFixture,
        );

        await mint(
          tokenProxy,
          deployer,
          wallets[0].address,
          ethers.parseEther("10"),
        );

        const amount = ethers.parseEther("1");
        const chainId = (await ethers.provider.getNetwork()).chainId;

        const name = await tokenProxy.name();

        const domain = {
          name: name,
          version: "1",
          chainId: chainId,
          verifyingContract: tokenProxy.target,
        };

        const typeHash = {
          TransferWithAuthorization: [
            { name: "from", type: "address" },
            { name: "to", type: "address" },
            { name: "value", type: "uint256" },
            { name: "validAfter", type: "uint256" },
            { name: "validBefore", type: "uint256" },
            { name: "nonce", type: "bytes32" },
          ],
        };

        const message = {
          from: wallets[0].address,
          to: wallets[1].address,
          value: amount.toString(),
          nonce: ethers.randomBytes(32),
          validAfter: Math.floor(Date.now() / 1000), // valid from now
          validBefore: Math.floor(Date.now() / 1000) + 3600, // valid for 1 hour
        };

        const signature = await wallets[0].signTypedData(
          domain,
          typeHash,
          message,
        );

        const { v, r, s } = ethers.Signature.from(signature);

        const cancelTypedData = {
          CancelAuthorization: [
            { name: "authorizer", type: "address" },
            { name: "nonce", type: "bytes32" },
          ],
        };

        const cancelMessage = {
          authorizer: wallets[0].address,
          nonce: message.nonce,
        };

        const cancelSignature = await wallets[0].signTypedData(
          domain,
          cancelTypedData,
          cancelMessage,
        );

        const { v: cv, r: cr, s: cs } = ethers.Signature.from(cancelSignature);

        const cancelTx = await tokenProxy
          .connect(wallets[0])
          .cancelAuthorization(wallets[0].address, message.nonce, cv, cr, cs);
        await cancelTx.wait();

        await expect(
          tokenProxy
            .connect(wallets[2])
            .transferWithAuthorization(
              message.from,
              message.to,
              message.value,
              message.validAfter,
              message.validBefore,
              message.nonce,
              v,
              r,
              s,
            ),
        ).to.be.revertedWithCustomError(tokenProxy, "InvalidAuthorization");
      });
      it("✨ receive tx with cancelled authorization should fail", async () => {
        const { tokenProxy, deployer, wallets } = await loadFixture(
          deployFixture,
        );

        await mint(
          tokenProxy,
          deployer,
          wallets[0].address,
          ethers.parseEther("10"),
        );

        const amount = ethers.parseEther("1");
        const chainId = (await ethers.provider.getNetwork()).chainId;

        const name = await tokenProxy.name();
        const domain = {
          name: name,
          version: "1",
          chainId: chainId,
          verifyingContract: tokenProxy.target,
        };

        const typeHash = {
          ReceiveWithAuthorization: [
            { name: "from", type: "address" },
            { name: "to", type: "address" },
            { name: "value", type: "uint256" },
            { name: "validAfter", type: "uint256" },
            { name: "validBefore", type: "uint256" },
            { name: "nonce", type: "bytes32" },
          ],
        };

        const message = {
          from: wallets[0].address,
          to: wallets[1].address,
          value: amount.toString(),
          nonce: ethers.randomBytes(32),
          validAfter: Math.floor(Date.now() / 1000), // valid from now
          validBefore: Math.floor(Date.now() / 1000) + 3600, // valid for 1 hour
        };

        const signature = await wallets[0].signTypedData(
          domain,
          typeHash,
          message,
        );

        const { v, r, s } = ethers.Signature.from(signature);

        const cancelTypedData = {
          CancelAuthorization: [
            { name: "authorizer", type: "address" },
            { name: "nonce", type: "bytes32" },
          ],
        };

        const cancelMessage = {
          authorizer: wallets[0].address,
          nonce: message.nonce,
        };

        const cancelSignature = await wallets[0].signTypedData(
          domain,
          cancelTypedData,
          cancelMessage,
        );

        const { v: cv, r: cr, s: cs } = ethers.Signature.from(cancelSignature);

        const cancelTx = await tokenProxy
          .connect(wallets[0])
          .cancelAuthorization(wallets[0].address, message.nonce, cv, cr, cs);
        await cancelTx.wait();

        await expect(
          tokenProxy
            .connect(wallets[1])
            .receiveWithAuthorization(
              message.from,
              message.to,
              message.value,
              message.validAfter,
              message.validBefore,
              message.nonce,
              v,
              r,
              s,
            ),
        ).to.be.revertedWithCustomError(tokenProxy, "InvalidAuthorization");
      });
    });
  });
  describe("Upgrade", () => {
    describe("Auditor Flow", () => {
      it("✨ Zero address cannot be set as audited implementation", async () => {
        const { tokenProxy, deployer, upgradeAuditor } = await loadFixture(
          deployFixture,
        );

        await grantRole(
          tokenProxy.connect(deployer),
          await tokenProxy.UPGRADE_AUDITOR_ROLE(),
          upgradeAuditor,
        );

        await expect(
          tokenProxy
            .connect(upgradeAuditor)
            .updateAuditedImpl(ethers.ZeroAddress),
        ).to.be.revertedWithCustomError(tokenProxy, "InvalidImplementation");
      });
      it("✨ Current implementation cannot be set as audited implementation", async () => {
        const { tokenProxy, proxy, deployer, upgradeAuditor } =
          await loadFixture(deployFixture);

        await grantRole(
          tokenProxy.connect(deployer),
          await tokenProxy.UPGRADE_AUDITOR_ROLE(),
          upgradeAuditor,
        );

        const curImpl = await proxy.getImplementation();

        await expect(
          tokenProxy.connect(upgradeAuditor).updateAuditedImpl(curImpl),
        ).to.be.revertedWithCustomError(tokenProxy, "InvalidImplementation");
      });
      it("✨ EOA address cannot be set as audited implementation", async () => {
        const { tokenProxy, proxy, deployer, upgradeAuditor, wallets } =
          await loadFixture(deployFixture);

        await grantRole(
          tokenProxy.connect(deployer),
          await tokenProxy.UPGRADE_AUDITOR_ROLE(),
          upgradeAuditor,
        );

        await expect(
          tokenProxy
            .connect(upgradeAuditor)
            .updateAuditedImpl(wallets[0].address),
        ).to.be.revertedWithCustomError(tokenProxy, "InvalidImplementation");
      });

      it("✨ only UPGRADE_AUDITOR_ROLE can call updateAuditedImpl() ", async () => {
        const { tokenProxy, deployer, implFac, upgradeAuditor, wallets } =
          await loadFixture(deployFixture);

        const newImpl = await implFac.deploy();
        await newImpl.waitForDeployment();

        await expect(
          tokenProxy.connect(wallets[0]).updateAuditedImpl(newImpl.target),
        ).to.be.revertedWithCustomError(
          tokenProxy,
          "AccessControlUnauthorizedAccount",
        );

        await grantRole(
          tokenProxy.connect(deployer),
          await tokenProxy.UPGRADE_AUDITOR_ROLE(),
          upgradeAuditor,
        );

        const auditDataBefore = await tokenProxy.getAuditedImplData();
        expect(auditDataBefore.auditedImpl).to.not.equal(newImpl.target);

        const auditTx = await tokenProxy
          .connect(upgradeAuditor)
          .updateAuditedImpl(newImpl.target);
        await auditTx.wait();

        const auditData = await tokenProxy.getAuditedImplData();
        expect(auditData.auditedImpl).to.equal(newImpl.target);
      });
      it("✨ audited Implementation should be updated correctly", async () => {
        const { tokenProxy, proxy, deployer, implFac, upgradeAuditor } =
          await loadFixture(deployFixture);

        await grantRole(
          tokenProxy.connect(deployer),
          await tokenProxy.UPGRADE_AUDITOR_ROLE(),
          upgradeAuditor,
        );

        const newImpl = await implFac.deploy();
        await newImpl.waitForDeployment();

        const auditTx = await tokenProxy
          .connect(upgradeAuditor)
          .updateAuditedImpl(newImpl.target);
        await auditTx.wait();

        const auditData = await tokenProxy.getAuditedImplData();
        expect(auditData.auditedImpl).to.equal(newImpl.target);
        expect(auditData.auditor).to.equal(upgradeAuditor.address);
        expect(auditData.isUpgraded).to.equal(false);
      });
    });
    describe("Upgrader Flow", () => {
      it("✨ only UPGRADER_ROLE can call upgradeToAndCall()", async () => {
        const {
          tokenProxy,
          proxy,
          implFac,
          deployer,
          upgradeAuditor,
          upgrader,
        } = await loadFixture(deployFixture);

        await grantRole(
          tokenProxy.connect(deployer),
          await tokenProxy.UPGRADE_AUDITOR_ROLE(),
          upgradeAuditor,
        );

        await grantRole(
          tokenProxy.connect(deployer),
          await tokenProxy.UPGRADER_ROLE(),
          upgrader,
        );

        const curImpl = await proxy.getImplementation();

        const newImpl = await implFac.deploy();
        await newImpl.waitForDeployment();

        const auditTx = await tokenProxy
          .connect(upgradeAuditor)
          .updateAuditedImpl(newImpl.target);
        await auditTx.wait();

        const auditData = await tokenProxy.getAuditedImplData();
        expect(auditData.auditedImpl).to.equal(newImpl.target);
        expect(auditData.isUpgraded).to.equal(false);

        const upgradeTx = await tokenProxy
          .connect(upgrader)
          .upgradeToAndCall(newImpl.target, "0x");
        await upgradeTx.wait();

        const upgradedImpl = await proxy.getImplementation();
        expect(upgradedImpl).to.equal(newImpl.target);

        const auditDataAfter = await tokenProxy.getAuditedImplData();
        expect(auditDataAfter.isUpgraded).to.equal(true);
      });
      it("✨ If the audit data is expired, upgrade should fail", async () => {
        const {
          tokenProxy,
          proxy,
          implFac,
          deployer,
          upgradeAuditor,
          upgrader,
        } = await loadFixture(deployFixture);

        await grantRole(
          tokenProxy.connect(deployer),
          await tokenProxy.UPGRADE_AUDITOR_ROLE(),
          upgradeAuditor,
        );

        await grantRole(
          tokenProxy.connect(deployer),
          await tokenProxy.UPGRADER_ROLE(),
          upgrader,
        );

        const curImpl = await proxy.getImplementation();

        const newImpl = await implFac.deploy();
        await newImpl.waitForDeployment();

        const auditTx = await tokenProxy
          .connect(upgradeAuditor)
          .updateAuditedImpl(newImpl.target);
        await auditTx.wait();

        const auditData = await tokenProxy.getAuditedImplData();
        expect(auditData.auditedImpl).to.equal(newImpl.target);
        expect(auditData.isUpgraded).to.equal(false);

        // 3days later
        await ethers.provider.send("evm_increaseTime", [
          3 * 24 * 60 * 60 + 3600,
        ]);
        await ethers.provider.send("evm_mine");

        await expect(
          tokenProxy.connect(upgrader).upgradeToAndCall(newImpl.target, "0x"),
        ).to.be.revertedWithCustomError(tokenProxy, "InvalidTimeframe");
      });

      it("✨ not audited address should be rejected", async () => {
        const { tokenProxy, proxy, implFac, deployer, upgrader } =
          await loadFixture(deployFixture);

        await grantRole(
          tokenProxy.connect(deployer),
          await tokenProxy.UPGRADER_ROLE(),
          upgrader,
        );

        await grantRole(
          tokenProxy.connect(deployer),
          await tokenProxy.UPGRADE_AUDITOR_ROLE(),
          upgrader,
        );

        const newImpl = await implFac.deploy();
        await newImpl.waitForDeployment();

        const newImpl2 = await implFac.deploy();
        await newImpl2.waitForDeployment();

        const auditTx = await tokenProxy
          .connect(upgrader)
          .updateAuditedImpl(newImpl.target);
        await auditTx.wait();

        const auditData = await tokenProxy.getAuditedImplData();
        expect(auditData.auditedImpl).to.equal(newImpl.target);
        expect(auditData.isUpgraded).to.equal(false);

        await expect(
          tokenProxy.connect(upgrader).upgradeToAndCall(newImpl2.target, "0x"),
        ).to.be.revertedWithCustomError(tokenProxy, "InvalidImplementation");
      });
    });
  });
});
