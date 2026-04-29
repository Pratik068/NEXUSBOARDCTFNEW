'use strict';
const ejs  = require('ejs');
const path = require('path');
const fs   = require('fs');

const VIEWS_DIR = path.join(__dirname, '..', 'views');

function render(name, locals) {
  const file     = path.join(VIEWS_DIR, name + '.ejs');
  const template = fs.readFileSync(file, 'utf8');
  return ejs.render(template, locals, { filename: file });
}

/** Express-compatible res.render replacement */
function renderMiddleware(req, res, next) {
  res.renderView = function (name, locals = {}) {
    try {
      const html = render(name, locals);
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(html);
    } catch (e) {
      console.error('Render error:', e);
      res.status(500).end('Render error');
    }
  };
  next();
}

module.exports = { renderMiddleware, render };
