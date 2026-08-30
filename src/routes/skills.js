import { Router } from 'express';
import { browseSkills, retrieveSkills, getSkill, skillStats } from '../services/skills/index.js';

// Phase 3 — /api/skills: browse, search, and read the 817 cybersecurity expert playbooks.
// Read-only knowledge (any logged-in user, behind the /api currentUser mount). Powers the Skills UI.
export const skillsRouter = Router();
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Deterministic browse + filter (paginated): ?q= &subdomain= &mitre=T1055 &nist= &limit= &offset=
skillsRouter.get('/', wrap(async (req, res) => {
  res.json(await browseSkills({
    q: req.query.q || '',
    subdomain: req.query.subdomain || '',
    mitre: req.query.mitre || '',
    nist: req.query.nist || '',
    limit: req.query.limit,
    offset: req.query.offset,
  }));
}));

// Semantic search (natural-language relevance): ?q=dump a database via sqli &k=6
skillsRouter.get('/search', wrap(async (req, res) => {
  const skills = await retrieveSkills(String(req.query.q || ''), Number(req.query.k) || 6);
  res.json({ skills });
}));

// Catalog stats + subdomain distribution (for filter chips).
skillsRouter.get('/stats', wrap(async (_req, res) => res.json(await skillStats())));

// Full playbook (SKILL.md body + frontmatter) by exact name.
skillsRouter.get('/:name', wrap(async (req, res) => {
  const skill = await getSkill(req.params.name);
  if (!skill) return res.status(404).json({ error: 'Skill not found' });
  res.json({ skill });
}));
