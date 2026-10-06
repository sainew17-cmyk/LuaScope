const express = require('express');
const app = express();

let botRef = null;

app.get('/', (req, res) => res.send('LuaScope is running'));
app.get('/health', (req, res) => {
  if (botRef && botRef.isReady()) {
    res.json({ status: 'ok', bot: botRef.user.tag });
  } else {
    res.json({ status: 'starting' });
  }
});

function start(bot) {
  botRef = bot;
  const port = process.env.PORT || 10000;
  app.listen(port, () => console.log(`[keep_alive] listening on ${port}`));
}

module.exports = { start };
