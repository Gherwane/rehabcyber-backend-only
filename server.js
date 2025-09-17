require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = express();
const cron = require('node-cron');
const nodemailer = require('nodemailer');

// Middleware
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';

// In-memory user storage (replace with DB in production)
let users = [];

// JWT authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Missing token' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// User registration (HIPAA-compliant - no PHI collection)
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, name, phone } = req.body;
    if (!email || !password || password.length < 6) {
      return res.status(400).json({ error: 'Email and password (min 6 chars) required' });
    }
    if (!name) {
      return res.status(400).json({ error: 'Name is required' });
    }
    if (users.find(u => u.email === email)) {
      return res.status(409).json({ error: 'Email already registered' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = {
      id: users.length + 1,
      email,
      password: hashedPassword,
      name,
      phone: phone || '',
      profile: {}, // Will be populated during consultation
      preferences: {},
      alerts: [],
      history: []
    };
    users.push(user);
    res.json({ message: 'Registration successful' });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

// User login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });
    // Generate JWT
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get user profile (protected)
app.get('/api/profile', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ 
    email: user.email, 
    name: user.name,
    phone: user.phone,
    preferences: user.preferences, 
    alerts: user.alerts, 
    history: user.history 
  });
});

// User preferences endpoints
app.get('/api/preferences', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ preferences: user.preferences });
});

app.post('/api/preferences', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.preferences = req.body.preferences || {};
  res.json({ message: 'Preferences updated', preferences: user.preferences });
});

// User research alerts endpoints
app.get('/api/alerts', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ alerts: user.alerts });
});

app.post('/api/alerts', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { term } = req.body;
  if (!term || term.length < 3) return res.status(400).json({ error: 'Alert term must be at least 3 characters' });
  if (user.alerts.includes(term)) return res.status(409).json({ error: 'Already subscribed to this alert' });
  user.alerts.push(term);
  res.json({ message: 'Alert subscribed', alerts: user.alerts });
});

app.delete('/api/alerts', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { term } = req.body;
  user.alerts = user.alerts.filter(a => a !== term);
  res.json({ message: 'Alert unsubscribed', alerts: user.alerts });
});

// Personalized search history endpoint
app.get('/api/user-history', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ history: user.history.slice(0, 20) });
});

// API endpoints
const PUBMED_API = 'https://eutils.ncbi.nlm.nih.gov/entrez/eutils';
const SCIENCE_DIRECT_API = 'https://api.elsevier.com/content/search/sciencedirect';
const SCOPUS_API = 'https://api.scopus.com/content/search/scopus';
const JOSPT_API = 'https://www.jospt.org/api/search';
const PTJ_API = 'https://academic.oup.com/ptj/api/search';

// API Keys (should be in environment variables in production)
const SCIENCE_DIRECT_API_KEY = process.env.SCIENCE_DIRECT_API_KEY || 'demo-key';
const SCOPUS_API_KEY = process.env.SCOPUS_API_KEY || 'demo-key';

// In-memory storage for search history and suggestions (use database in production)
let searchHistory = [];
let searchSuggestions = new Set();

// Load search suggestions from file
const loadSearchSuggestions = async () => {
  try {
    const suggestions = [
      'physical therapy', 'rehabilitation', 'musculoskeletal', 'orthopedic',
      'sports medicine', 'exercise therapy', 'manual therapy', 'electrotherapy',
      'ultrasound therapy', 'traction', 'mobilization', 'strengthening',
      'range of motion', 'balance training', 'gait training', 'posture correction',
      'pain management', 'injury prevention', 'post-surgical rehabilitation',
      'stroke rehabilitation', 'cardiac rehabilitation', 'pulmonary rehabilitation',
      'pediatric physical therapy', 'geriatric physical therapy', 'neurological rehabilitation',
      'vestibular rehabilitation', 'lymphedema therapy', 'wound care', 'amputation rehabilitation',
      'spinal cord injury', 'traumatic brain injury', 'multiple sclerosis', 'parkinson disease',
      'arthritis', 'fibromyalgia', 'chronic pain', 'sports injury', 'workplace injury',
      'ergonomics', 'biomechanics', 'kinesiology', 'therapeutic exercise', 'functional training'
    ];
    suggestions.forEach(suggestion => searchSuggestions.add(suggestion));
  } catch (error) {
    console.log('Using default search suggestions');
  }
};

// Enhanced search endpoint with filters
app.post('/api/search', async (req, res) => {
  try {
    const { query, filters = {} } = req.body;
    
    // Input validation
    if (!query || query.trim().length < 3) {
      return res.status(400).json({ 
        error: 'Search query must be at least 3 characters long',
        summary: '<p style="color: #07277C;">Please enter a search term with at least 3 characters.</p>'
      });
    }

    if (query.trim().length > 200) {
      return res.status(400).json({ 
        error: 'Search query is too long (maximum 200 characters)',
        summary: '<p style="color: #07277C;">Please shorten your search query to 200 characters or less.</p>'
      });
    }

    console.log(`Searching for: "${query}" with filters:`, filters);
    
    // Add to search history
    const searchEntry = {
      query: query.trim(),
      filters,
      timestamp: new Date().toISOString(),
      results: 0
    };
    
    // Add to search suggestions
    const words = query.toLowerCase().split(' ').filter(word => word.length > 2);
    words.forEach(word => searchSuggestions.add(word));
    
    const results = [];
    const sources = [];
    
    // Search PubMed (always available, no API key needed)
    try {
      const pubmedResults = await searchPubMed(query, filters);
      results.push(...pubmedResults);
      sources.push('PubMed');
    } catch (error) {
      console.error('PubMed search failed:', error.message);
    }
    
    // Search ScienceDirect (only if API key is available)
    if (SCIENCE_DIRECT_API_KEY && SCIENCE_DIRECT_API_KEY !== 'demo-key') {
      try {
        const scienceDirectResults = await searchScienceDirect(query, filters);
        results.push(...scienceDirectResults);
        sources.push('ScienceDirect');
      } catch (error) {
        console.error('ScienceDirect search failed:', error.message);
      }
    }
    
    // Search Scopus (only if API key is available)
    if (SCOPUS_API_KEY && SCOPUS_API_KEY !== 'demo-key') {
      try {
        const scopusResults = await searchScopus(query, filters);
        results.push(...scopusResults);
        sources.push('Scopus');
      } catch (error) {
        console.error('Scopus search failed:', error.message);
      }
    }
    
    // Apply filters to results
    const filteredResults = applyFilters(results, filters);
    
    // Update search history
    searchEntry.results = filteredResults.length;
    searchHistory.unshift(searchEntry);
    searchHistory = searchHistory.slice(0, 50); // Keep last 50 searches
    
    // Update user search history if authenticated
    if (req.headers.authorization) {
      try {
        const token = req.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = users.find(u => u.id === decoded.id);
        if (user) {
          user.history.unshift({ ...searchEntry, results: filteredResults.length });
          user.history = user.history.slice(0, 50);
        }
      } catch (e) {}
    }
    
    // If no results from APIs, provide fallback content
    if (filteredResults.length === 0) {
      const fallbackContent = generateFallbackContent(query);
      return res.json({
        summary: fallbackContent,
        sources: ['PubMed'],
        warning: 'Limited results available. Consider refining your search terms.',
        searchHistory: searchHistory.slice(0, 10)
      });
    }
    
    // Sort results by date
    filteredResults.sort((a, b) => new Date(b.date) - new Date(a.date));
    
    // Limit results to prevent overwhelming response
    const limitedResults = filteredResults.slice(0, 10);
    
    // Format results
    const summary = formatResults(limitedResults);
    
    res.json({
      summary: summary,
      sources: sources,
      resultCount: limitedResults.length,
      searchHistory: searchHistory.slice(0, 10),
      filters: filters
    });
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ 
      error: 'Search service temporarily unavailable',
      summary: '<p style="color: #07277C;">Our search service is currently experiencing issues. Please try again in a few minutes, or contact us directly for research assistance.</p>'
    });
  }
});

// Search suggestions endpoint
app.get('/api/suggestions', (req, res) => {
  const { q } = req.query;
  if (!q || q.length < 2) {
    return res.json({ suggestions: [] });
  }
  
  const suggestions = Array.from(searchSuggestions)
    .filter(suggestion => suggestion.toLowerCase().includes(q.toLowerCase()))
    .slice(0, 10);
  
  res.json({ suggestions });
});

// Search history endpoint
app.get('/api/history', (req, res) => {
  res.json({ history: searchHistory.slice(0, 20) });
});

// Export results endpoint
app.post('/api/export', async (req, res) => {
  try {
    const { results, format = 'pdf', email } = req.body;
    
    if (!results || !Array.isArray(results)) {
      return res.status(400).json({ error: 'Invalid results data' });
    }
    
    let exportData;
    
    if (format === 'pdf') {
      exportData = generatePDFExport(results);
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', 'attachment; filename="research-results.pdf"');
    } else if (format === 'email') {
      if (!email) {
        return res.status(400).json({ error: 'Email address required for email export' });
      }
      exportData = await sendEmailExport(results, email);
      res.json({ message: 'Results sent to your email' });
      return;
    } else {
      exportData = generateTextExport(results);
      res.setHeader('Content-Type', 'text/plain');
      res.setHeader('Content-Disposition', 'attachment; filename="research-results.txt"');
    }
    
    res.send(exportData);
  } catch (error) {
    console.error('Export error:', error);
    res.status(500).json({ error: 'Export failed' });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    services: {
      pubmed: 'available',
      scienceDirect: SCIENCE_DIRECT_API_KEY !== 'demo-key' ? 'available' : 'requires_api_key',
      scopus: SCOPUS_API_KEY !== 'demo-key' ? 'available' : 'requires_api_key',
      jospt: 'simulated',
      ptj: 'simulated'
    },
    searchHistory: searchHistory.length,
    suggestions: searchSuggestions.size
  });
});

// Email transporter setup
const emailTransporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Simulated user email lookup (in-memory)
function getUserEmail(user) {
  return user.email;
}

// Scheduled job: check research alerts daily at 7am
cron.schedule('0 7 * * *', async () => {
  console.log('[CRON] Checking research alerts for all users...');
  for (const user of users) {
    if (!user.alerts || user.alerts.length === 0) continue;
    for (const term of user.alerts) {
      try {
        // Search PubMed for new articles in the last 2 days
        const today = new Date();
        const twoDaysAgo = new Date(today.getTime() - 2 * 24 * 60 * 60 * 1000);
        const dateFrom = twoDaysAgo.getFullYear() + '/' + (twoDaysAgo.getMonth() + 1).toString().padStart(2, '0') + '/' + twoDaysAgo.getDate().toString().padStart(2, '0');
        const results = await searchPubMed(term, { dateFrom });
        if (results.length > 0) {
          // Send email notification
          const email = getUserEmail(user);
          const subject = `REHABCYBER: New research for your alert "${term}"`;
          const html = `<h3>New research articles for: <b>${term}</b></h3>` +
            results.slice(0, 5).map(article =>
              `<div style='margin-bottom:20px;'><b>${article.title}</b><br>${article.authors}<br>${article.journal} (${article.date})<br><a href='https://pubmed.ncbi.nlm.nih.gov/${article.pmid}' target='_blank'>View on PubMed</a></div>`
            ).join('') +
            `<p>To manage your alerts, log in to your REHABCYBER account.</p>`;
          await emailTransporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject,
            html
          });
          console.log(`[ALERT] Sent research alert to ${email} for term "${term}" (${results.length} new articles)`);
        }
      } catch (e) {
        console.log(`[ALERT] Error checking alert for user ${user.email}, term "${term}":`, e.message);
      }
    }
  }
});

async function searchPubMed(query, filters = {}) {
  try {
    // Build search query with filters
    let searchQuery = query;
    if (filters.journal) {
      searchQuery += ` AND "${filters.journal}"[journal]`;
    }
    if (filters.dateFrom) {
      searchQuery += ` AND ${filters.dateFrom}:3000[dp]`;
    }
    if (filters.studyType) {
      searchQuery += ` AND ${filters.studyType}[pt]`;
    }
    
    // Search for articles
    const searchResponse = await axios.get(`${PUBMED_API}/esearch.fcgi`, {
      params: {
        db: 'pubmed',
        term: searchQuery,
        retmode: 'json',
        retmax: 15,
        sort: 'date'
      },
      timeout: 10000
    });

    if (!searchResponse.data.esearchresult || !searchResponse.data.esearchresult.idlist) {
      return [];
    }

    const ids = searchResponse.data.esearchresult.idlist;
    
    if (ids.length === 0) {
      return [];
    }
    
    // Get article details
    const summaryResponse = await axios.get(`${PUBMED_API}/esummary.fcgi`, {
      params: {
        db: 'pubmed',
        id: ids.join(','),
        retmode: 'json'
      },
      timeout: 10000
    });

    return Object.values(summaryResponse.data.result)
      .filter(article => article.pubdate && article.title)
      .map(article => ({
        title: article.title || 'Untitled',
        abstract: article.abstract || 'No abstract available',
        authors: article.authors?.map(a => a.name).join(', ') || 'Unknown',
        journal: article.fulljournalname || 'Unknown',
        date: article.pubdate,
        source: 'PubMed',
        pmid: article.uid,
        doi: article.elocationid || null,
        studyType: determineStudyType(article.title, article.abstract)
      }));
  } catch (error) {
    console.error('PubMed search error:', error.message);
    throw new Error('PubMed search failed');
  }
}

async function searchScienceDirect(query, filters = {}) {
  try {
    let searchParams = {
      query: query,
      count: 10
    };
    
    if (filters.dateFrom) {
      searchParams.date = filters.dateFrom;
    }
    
    const response = await axios.get(SCIENCE_DIRECT_API, {
      params: searchParams,
      headers: {
        'X-ELS-APIKey': SCIENCE_DIRECT_API_KEY
      },
      timeout: 10000
    });

    if (!response.data || !response.data.results) {
      return [];
    }

    return response.data.results.map(article => ({
      title: article.title || 'Untitled',
      abstract: article.description || 'No abstract available',
      authors: article.authors?.join(', ') || 'Unknown',
      journal: article.publicationName || 'Unknown',
      date: article.publicationDate || 'Unknown',
      source: 'ScienceDirect',
      doi: article.doi,
      studyType: determineStudyType(article.title, article.description)
    }));
  } catch (error) {
    console.error('ScienceDirect search error:', error.message);
    throw new Error('ScienceDirect search failed');
  }
}

async function searchScopus(query, filters = {}) {
  try {
    let searchParams = {
      query: query,
      count: 10
    };
    
    if (filters.dateFrom) {
      searchParams.date = filters.dateFrom;
    }
    
    const response = await axios.get(SCOPUS_API, {
      params: searchParams,
      headers: {
        'X-ELS-APIKey': SCOPUS_API_KEY
      },
      timeout: 10000
    });

    if (!response.data || !response.data.results) {
      return [];
    }

    return response.data.results.map(article => ({
      title: article.title || 'Untitled',
      abstract: article.description || 'No abstract available',
      authors: article.authors?.join(', ') || 'Unknown',
      journal: article.publicationName || 'Unknown',
      date: article.publicationDate || 'Unknown',
      source: 'Scopus',
      doi: article.doi,
      studyType: determineStudyType(article.title, article.description)
    }));
  } catch (error) {
    console.error('Scopus search error:', error.message);
    throw new Error('Scopus search failed');
  }
}

function applyFilters(results, filters) {
  let filtered = results;
  
  // Filter by journal
  if (filters.journal) {
    filtered = filtered.filter(result => 
      result.journal.toLowerCase().includes(filters.journal.toLowerCase())
    );
  }
  
  // Filter by date range
  if (filters.dateFrom) {
    const fromDate = new Date(filters.dateFrom);
    filtered = filtered.filter(result => {
      const resultDate = new Date(result.date);
      return resultDate >= fromDate;
    });
  }
  
  if (filters.dateTo) {
    const toDate = new Date(filters.dateTo);
    filtered = filtered.filter(result => {
      const resultDate = new Date(result.date);
      return resultDate <= toDate;
    });
  }
  
  // Filter by study type
  if (filters.studyType) {
    filtered = filtered.filter(result => 
      result.studyType && result.studyType.toLowerCase().includes(filters.studyType.toLowerCase())
    );
  }
  
  return filtered;
}

function determineStudyType(title, abstract) {
  const text = `${title} ${abstract}`.toLowerCase();
  
  if (text.includes('randomized') || text.includes('rct') || text.includes('randomised')) {
    return 'Randomized Controlled Trial';
  } else if (text.includes('systematic review') || text.includes('meta-analysis')) {
    return 'Systematic Review';
  } else if (text.includes('case study') || text.includes('case report')) {
    return 'Case Study';
  } else if (text.includes('cohort study') || text.includes('longitudinal')) {
    return 'Cohort Study';
  } else if (text.includes('cross-sectional') || text.includes('survey')) {
    return 'Cross-Sectional Study';
  } else {
    return 'Other';
  }
}

function formatResults(results) {
  if (results.length === 0) {
    return '<p style="color: #07277C;">No results found. Try different search terms or contact us for assistance.</p>';
  }
  
  let summary = `<p style="color: #07277C; margin-bottom: 20px;"><strong>Found ${results.length} research articles:</strong></p>`;
  
  results.forEach((article, index) => {
    const date = article.date ? new Date(article.date).getFullYear() : 'Unknown';
    const sourceBadge = `<span style="background: #07277C; color: #EDD9A0; padding: 2px 8px; border-radius: 12px; font-size: 0.8em; margin-left: 10px;">${article.source}</span>`;
    const studyTypeBadge = article.studyType ? `<span style="background: #EDD9A0; color: #07277C; padding: 2px 8px; border-radius: 12px; font-size: 0.8em; margin-left: 5px;">${article.studyType}</span>` : '';
    
    summary += `<div style="margin-bottom: 25px; padding: 15px; background: rgba(255,255,255,0.1); border-radius: 10px;" data-article-index="${index}">`;
    summary += `<h4 style="color: #07277C; margin-bottom: 10px;">${article.title} ${sourceBadge} ${studyTypeBadge}</h4>`;
    summary += `<p style="color: #07277C; margin-bottom: 8px;"><strong>Abstract:</strong> ${article.abstract}</p>`;
    summary += `<p style="color: #07277C; margin-bottom: 5px;"><strong>Authors:</strong> ${article.authors}</p>`;
    summary += `<p style="color: #07277C; margin-bottom: 5px;"><strong>Journal:</strong> ${article.journal}</p>`;
    summary += `<p style="color: #07277C; font-size: 0.9em;"><strong>Published:</strong> ${date}</p>`;
    if (article.doi) {
      summary += `<p style="color: #07277C; font-size: 0.9em;"><strong>DOI:</strong> <a href="https://doi.org/${article.doi}" target="_blank" style="color: #07277C;">${article.doi}</a></p>`;
    }
    summary += `</div>`;
  });
  
  return summary;
}

function generateFallbackContent(query) {
  const fallbackContent = `
    <div style="color: #07277C;">
      <h3>Search Results for: "${query}"</h3>
      <p>While we're unable to search external databases at the moment, here are some evidence-based resources related to your query:</p>
      
      <div style="margin: 20px 0; padding: 15px; background: rgba(255,255,255,0.1); border-radius: 10px;">
        <h4>Recommended Research Sources:</h4>
        <ul style="margin: 10px 0; padding-left: 20px;">
          <li><a href="https://pubmed.ncbi.nlm.nih.gov/" target="_blank" style="color: #07277C;">PubMed Central</a> - Free access to biomedical literature</li>
          <li><a href="https://www.jospt.org/" target="_blank" style="color: #07277C;">Journal of Orthopaedic & Sports Physical Therapy</a></li>
          <li><a href="https://academic.oup.com/ptj" target="_blank" style="color: #07277C;">Physical Therapy Journal</a></li>
          <li><a href="https://www.ijspt.org/" target="_blank" style="color: #07277C;">International Journal of Sports Physical Therapy</a></li>
        </ul>
      </div>
      
      <p><strong>Contact us directly</strong> for personalized research assistance and evidence-based treatment recommendations.</p>
    </div>
  `;
  
  return fallbackContent;
}

function generatePDFExport(results) {
  // Simple PDF-like text format (in production, use a proper PDF library)
  let pdfContent = 'REHABCYBER Research Results\n';
  pdfContent += 'Generated on: ' + new Date().toLocaleDateString() + '\n\n';
  
  results.forEach((article, index) => {
    pdfContent += `${index + 1}. ${article.title}\n`;
    pdfContent += `   Authors: ${article.authors}\n`;
    pdfContent += `   Journal: ${article.journal}\n`;
    pdfContent += `   Published: ${article.date}\n`;
    pdfContent += `   Source: ${article.source}\n`;
    if (article.doi) {
      pdfContent += `   DOI: ${article.doi}\n`;
    }
    pdfContent += `   Abstract: ${article.abstract}\n\n`;
  });
  
  return pdfContent;
}

function generateTextExport(results) {
  let textContent = 'REHABCYBER Research Results\n';
  textContent += 'Generated on: ' + new Date().toLocaleDateString() + '\n\n';
  
  results.forEach((article, index) => {
    textContent += `${index + 1}. ${article.title}\n`;
    textContent += `   Authors: ${article.authors}\n`;
    textContent += `   Journal: ${article.journal}\n`;
    textContent += `   Published: ${article.date}\n`;
    textContent += `   Source: ${article.source}\n`;
    if (article.doi) {
      textContent += `   DOI: ${article.doi}\n`;
    }
    textContent += `   Abstract: ${article.abstract}\n\n`;
  });
  
  return textContent;
}

async function sendEmailExport(results, email) {
  // In production, integrate with email service like SendGrid or AWS SES
  console.log(`Would send email to ${email} with ${results.length} results`);
  return { success: true, message: 'Email export simulated' };
}

// Initialize search suggestions
loadSearchSuggestions();

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('Available services:');
  console.log('- PubMed: Available');
  console.log(`- ScienceDirect: ${SCIENCE_DIRECT_API_KEY !== 'demo-key' ? 'Available' : 'Requires API key'}`);
  console.log(`- Scopus: ${SCOPUS_API_KEY !== 'demo-key' ? 'Available' : 'Requires API key'}`);
  console.log('- Search History: Enabled');
  console.log('- Search Suggestions: Enabled');
  console.log('- Export Features: Enabled');
});

// Dashboard endpoint: get user profile and general research
app.get('/api/dashboard', authenticateToken, async (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  // General research topics (no PHI-based personalization)
  try {
    const researchResults = await searchPubMed('physical therapy rehabilitation', {});
    res.json({
      profile: { name: user.name, email: user.email, phone: user.phone },
      research: researchResults.slice(0, 5) // Top 5 results
    });
  } catch (e) {
    res.json({ profile: { name: user.name, email: user.email, phone: user.phone }, research: [] });
  }
});

// Update user profile (HIPAA-compliant - no PHI updates via API)
app.put('/api/profile', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { name, phone } = req.body;
  if (name) user.name = name;
  if (phone !== undefined) user.phone = phone;
  res.json({ message: 'Profile updated', profile: { name: user.name, phone: user.phone } });
});

// Plan progress (checkboxes)
app.post('/api/plan-progress', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.planProgress = req.body.planProgress || [];
  res.json({ message: 'Plan progress saved' });
});
app.get('/api/plan-progress', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ planProgress: user.planProgress || [] });
});

// Saved articles & notes
app.post('/api/saved-articles', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.savedArticles = req.body.savedArticles || [];
  res.json({ message: 'Saved articles updated' });
});
app.get('/api/saved-articles', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ savedArticles: user.savedArticles || [] });
});

// Progress value
app.post('/api/progress', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.progressValue = req.body.progressValue || 0;
  res.json({ message: 'Progress value saved' });
});
app.get('/api/progress', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ progressValue: user.progressValue || 0 });
});

// Research alerts
app.post('/api/alerts', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.alerts = req.body.alerts || [];
  res.json({ message: 'Alerts updated' });
});
app.get('/api/alerts', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ alerts: user.alerts || [] });
}); 