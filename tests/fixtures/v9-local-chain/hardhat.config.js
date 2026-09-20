export default {
  networks: {
    v9local: {
      type: "edr-simulated",
      chainType: "l1",
      chainId: 31337,
      hardfork: "prague",
      // Recomputed for each fixture node; snapshot/warp tests advance from here.
      initialDate: new Date(Date.now() - 120000).toISOString(),
    },
  },
};
