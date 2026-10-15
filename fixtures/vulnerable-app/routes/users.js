// Fixture dotation : affectation de masse. Ne pas corriger.
module.exports = (app, User) => {
  app.post("/users", async (req, res) => {
    const user = new User(req.body);
    await user.save();
    res.json(user);
  });
};
