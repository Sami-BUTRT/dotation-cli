// Fixture dotation : en-tête CORS ouvert à tous. Ne pas corriger.
module.exports = {
  productionBrowserSourceMaps: true,
  async headers() {
    return [
      {
        source: "/api/:path*",
        headers: [{ key: "Access-Control-Allow-Origin", value: "*" }],
      },
    ];
  },
};
