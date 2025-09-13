'use client';

import React, { useEffect, useMemo, useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { LineChart, Line, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";
import { ShieldCheck, LockKeyhole, Plus, LogOut, Save, Trash2, ChevronLeft, ChevronRight } from "lucide-react";

interface Category {
  id: string;
  name: string;
  amount: number;
  currency?: string;
  remarks?: string;
}

interface Entry {
  id: string;
  categoryId: string;
  amount: number;
  dateISO: string;
}

interface Currency {
  code: string;
  rate: number;
}

interface HistoryItem {
  id: string;
  ts: string;
  type: string;
  entry?: Entry;
  category?: Category;
}


// ==========================
// Utility: Web Crypto helpers
// ==========================
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function b64encode(buf) {
  return typeof window === 'undefined' ? '' : btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function b64decode(b64) {
  if (typeof window === 'undefined') return new ArrayBuffer(0);
  const binStr = atob(b64);
  const bytes = new Uint8Array(binStr.length);
  for (let i = 0; i < binStr.length; i++) bytes[i] = binStr.charCodeAt(i);
  return bytes.buffer;
}
function toHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes.buffer;
}
function randBytes(n = 16) {
  const a = new Uint8Array(n);
  if (typeof window !== 'undefined' && window.crypto) window.crypto.getRandomValues(a);
  return a.buffer;
}
async function pbkdf2(password, salt, iterations = 210000, length = 32) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt, iterations, hash: 'SHA-256' },
    keyMaterial,
    length * 8
  );
  return bits; // ArrayBuffer
}
async function getAesKeyFromPassword(password, salt) {
  const bits = await pbkdf2(password, salt, 210000, 32);
  return await crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
async function sha256(buf) {
  return await crypto.subtle.digest('SHA-256', buf);
}
async function hashAnswer(answer, saltBytes) {
  const norm = answer.trim().toLowerCase();
  const concat = new Uint8Array([...textEncoder.encode(norm), ...new Uint8Array(saltBytes)]);
  const digest = await sha256(concat.buffer);
  return b64encode(digest);
}

async function encryptJson(obj, key) {
  const iv = randBytes(12);
  const plaintext = textEncoder.encode(JSON.stringify(obj));
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, plaintext);
  return { iv: b64encode(iv), ciphertext: b64encode(cipher) };
}
async function decryptJson(ciphertextB64, ivB64, key) {
  const cipher = b64decode(ciphertextB64);
  const iv = b64decode(ivB64);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, cipher);
  return JSON.parse(textDecoder.decode(plain));
}

// ==========================
// Currency formatting helpers
// ==========================
const SYMBOLS = { BDT: '৳', USD: '$', EUR: '€', GBP: '£', INR: '₹', JPY: '¥', CNY: '¥', AUD: 'A$', CAD: 'C$', SGD: 'S$', HKD: 'HK$', PKR: '₨', LKR: '₨', NPR: '₨' };
function symbolFor(code){ const c = (code||'').toUpperCase(); return SYMBOLS[c] || null; }
function formatAmount(code, amount){
  const sym = symbolFor(code);
  if (sym) return `${sym} ${Number(amount||0).toLocaleString()}`;
  try { return new Intl.NumberFormat(undefined, { style: 'currency', currency: (code||'').toUpperCase() }).format(Number(amount||0)); }
  catch { return `${(code||'').toUpperCase()} ${Number(amount||0).toLocaleString()}`; }
}

// ==========================
// Storage schema (local-only for v1)
// ==========================
/**
 * localStorage key: PF_E2EE_V1
 * {
 *   version: 1,
 *   user: { firstName: string },
 *   auth: { saltPwdHex, verifierHex, qas: [{ q, saltB64, hashB64 }] },
 *   enc: { saltEncHex, ivB64, ciphertextB64 }
 * }
 */
const LS_KEY = 'PF_E2EE_V1';

function loadState() {
  if (typeof window === 'undefined') return null;
  const raw = localStorage.getItem(LS_KEY);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}
function saveState(obj) {
  if (typeof window === 'undefined') return;
  localStorage.setItem(LS_KEY, JSON.stringify(obj));
}
function clearState() {
  if (typeof window === 'undefined') return;
  localStorage.removeItem(LS_KEY);
}

// ==========================
// App Data Types
// ==========================
// data (encrypted): { categories: [{id,name,amount,remarks}], entries: [{id,dateISO,categoryId,amount}] }

function newId() {
  return crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2);
}

// ==========================
// UI subcomponents
// ==========================
function Header({ firstName, onLogout }) {
  return (
    <div className="flex items-center justify-between px-4 py-3 border-b bg-white/70 backdrop-blur rounded-t-2xl">
      <div className="flex items-center gap-2">
        <ShieldCheck className="w-5 h-5" />
        <h1 className="text-xl font-semibold">Hi, {firstName || 'Arif'} 👋</h1>
      </div>
      <div className="flex items-center gap-2">
        <Button variant="outline" onClick={onLogout} className="gap-2"><LogOut className="w-4 h-4"/>Logout</Button>
      </div>
    </div>
  );
}

function Sidebar({ onAddCategory, categories, currencies, baseCurrency, onDeleteCategory }) {
  const [name, setName] = useState("");
  const [amount, setAmount] = useState("");
  const [remarks, setRemarks] = useState("");
  const [currency, setCurrency] = useState(baseCurrency || 'BDT');
  const codes = useMemo(()=> Array.from(new Set([...(currencies||[]).map(c=> (c.code||'').toUpperCase()), (baseCurrency||'BDT').toUpperCase()])), [currencies, baseCurrency]);

  return (
    <aside className="w-full sm:w-72 border-r bg-white/70 backdrop-blur rounded-l-2xl p-4 space-y-4">
      <div className="flex items-center gap-2">
        <LockKeyhole className="w-4 h-4"/>
        <h2 className="font-semibold">Categories</h2>
      </div>

      <div className="space-y-2">
        <Input placeholder="Name (e.g., Cash)" value={name} onChange={(e)=>setName(e.target.value)} />
        <Input placeholder="Amount" type="number" value={amount} onChange={(e)=>setAmount(e.target.value)} />
        <Select value={currency} onValueChange={setCurrency}>
          <SelectTrigger><SelectValue placeholder="Currency"/></SelectTrigger>
          <SelectContent>
            {codes.map((code:string) => <SelectItem key={code} value={code}>{code}</SelectItem>)}
          </SelectContent>
        </Select>
        <Textarea placeholder="Remarks" value={remarks} onChange={(e)=>setRemarks(e.target.value)} />
        <Button className="w-full gap-2" onClick={()=>{
          if(!name) return;
          onAddCategory({ id: newId(), name, amount: Number(amount||0), currency, remarks });
          setName(""); setAmount(""); setRemarks(""); setCurrency(baseCurrency || 'BDT');
        }}><Plus className="w-4 h-4"/>Add Category</Button>
      </div>

      <div className="pt-2">
        <h3 className="text-sm font-medium mb-2">Existing</h3>
        <div className="space-y-2 max-h-72 overflow-auto pr-1">
          {categories.length === 0 && <p className="text-sm text-slate-500">No categories yet.</p>}
          {categories.map(c => (
            <Card key={c.id} className="border-slate-200">
              <CardContent className="p-3 text-sm">
                <div className="font-semibold">{c.name}</div>
                <div className="text-slate-600">Amount: {formatAmount(c.currency || baseCurrency, c.amount)}</div>
                {c.remarks && <div className="text-slate-500">{c.remarks}</div>}
                <div className="mt-2 flex justify-end">
                  <Button variant="ghost" size="sm" className="text-red-600 hover:text-red-700" onClick={()=>onDeleteCategory(c.id)}><Trash2 className="w-4 h-4 mr-1"/>Delete</Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </aside>
  );
}

function AddEntry({ categories, onAdd }) {
  const [categoryId, setCategoryId] = useState(categories[0]?.id || "");
  const [amount, setAmount] = useState("");
  const [date, setDate] = useState(()=> new Date().toISOString().slice(0,10));

  useEffect(()=>{
    if(categories.length && !categoryId) setCategoryId(categories[0].id);
  }, [categories]);

  return (
    <div className="flex flex-wrap gap-2 items-end">
      <div className="w-48">
        <Select value={categoryId} onValueChange={setCategoryId}>
          <SelectTrigger><SelectValue placeholder="Category"/></SelectTrigger>
          <SelectContent>
            {categories.map(c => <SelectItem key={c.id} value={c.id}>{c.name}</SelectItem>)}
          </SelectContent>
        </Select>
      </div>
      <Input className="w-40" type="number" placeholder="Amount" value={amount} onChange={(e)=>setAmount(e.target.value)} />
      <Input className="w-44" type="date" value={date} onChange={(e)=>setDate(e.target.value)} />
      <Button onClick={()=>{
        if(!categoryId || !amount) return;
        onAdd({ id: newId(), categoryId, amount: Number(amount), dateISO: new Date(date).toISOString() });
        setAmount("");
      }} className="gap-2"><Save className="w-4 h-4"/>Add Savings Entry</Button>
    </div>
  );
}

function TotalsBar({ data, onAddCurrency, onSetBaseCurrency, onRemoveCurrency }) {
  const [showMgr, setShowMgr] = useState(false);
  const [newCode, setNewCode] = useState("");
  const [newRate, setNewRate] = useState("");
  const base = data.baseCurrency || 'BDT';
  const currencies = (data.currencies && data.currencies.length) ? data.currencies : [{ code: base, rate: 1 }];

  const totalBase = useMemo(() => {
  const base = (data.baseCurrency||'BDT').toUpperCase();
  const rates = new Map<string, number>((data.currencies||[]).map((c:Currency) => [String(c.code||'').toUpperCase(), Number(c.rate)||0]));
  const getRate = (code?:string): number => {
    const cc = (code||base).toUpperCase();
    if (cc===base) return 1;
    return (rates.get(cc) ?? 1);
  };
  return data.categories.reduce((s:number,c:Category)=>{
    const amt = Number(c.amount)||0;
    const r:number = getRate(c.currency);
    return s + (r ? (amt / r) : amt);
  }, 0);
}, [data.categories, data.currencies, data.baseCurrency]);


  const displayCurrencies = useMemo(() => {
    const seen = new Set();
    const arr = [];
    const all = [...currencies];
    if (!all.find(c=> (c.code||'').toUpperCase() === base.toUpperCase())) all.unshift({ code: base, rate: 1 });
    for (const c of all) {
      const code = (c.code||'').toUpperCase();
      if (!code || seen.has(code)) continue; seen.add(code);
      const amount = totalBase * (Number(c.rate)||0);
      const formatted = formatAmount(code, amount);
      
      
      
      arr.push({ code, formatted });
    }
    return arr;
  }, [currencies, base, totalBase]);

  return (
    <div className="px-4 py-3 border-b bg-white/60">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="text-sm text-slate-700">
          <span className="font-medium">Total assets</span>{' '}<span className="text-slate-500">(base: {base})</span>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="outline" onClick={()=>setShowMgr(v=>!v)}>{showMgr ? 'Done' : 'Manage currencies'}</Button>
        </div>
      </div>
      <div className="mt-2 flex flex-wrap gap-3">
        {displayCurrencies.map(({ code, formatted }) => (
          <div key={code} className="px-3 py-2 rounded-xl bg-slate-100 text-sm"><span className="font-medium mr-2">{code}</span><span>{formatted}</span></div>
        ))}
        {displayCurrencies.length===0 && <div className="text-sm text-slate-500">Add a category to see totals.</div>}
      </div>
      {showMgr && (
        <div className="mt-3 grid sm:grid-cols-3 gap-2">
          <div className="sm:col-span-1">
            <label className="text-xs text-slate-500">Base currency</label>
            <Select value={base} onValueChange={(v)=>onSetBaseCurrency(v)}>
              <SelectTrigger><SelectValue placeholder="Base"/></SelectTrigger>
              <SelectContent>
                {Array.from(new Set((currencies||[]).map(c=>(c.code||'').toUpperCase()).concat([base.toUpperCase()]))).map(code => (
                  <SelectItem key={code} value={code}>{code}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex gap-2 items-end sm:col-span-2">
            <div className="w-32">
              <label className="text-xs text-slate-500">Currency code</label>
              <Input value={newCode} onChange={(e)=>setNewCode(e.target.value.toUpperCase())} placeholder="e.g., USD" />
            </div>
            <div className="w-40">
              <label className="text-xs text-slate-500">Rate (1 {base} = ?)</label>
              <Input type="number" step="any" value={newRate} onChange={(e)=>setNewRate(e.target.value)} placeholder="e.g., 0.0085" />
            </div>
            <Button onClick={()=>{ if(!newCode||!newRate) return; onAddCurrency({ code: newCode, rate: Number(newRate) }); setNewCode(''); setNewRate(''); }} className="whitespace-nowrap">Add / Update</Button>
          </div>
          <div className="sm:col-span-3">
            <div className="text-xs text-slate-500 mb-1">Existing currencies</div>
            <div className="flex flex-wrap gap-2">
              {(currencies||[]).map(c => (
                <div key={c.code} className="flex items-center gap-2 px-2 py-1 rounded-lg bg-slate-100">
                  <span className="text-sm font-medium">{String(c.code||'').toUpperCase()}</span>
                  <span className="text-xs text-slate-600">1 {base} = {c.rate} {String(c.code||'').toUpperCase()}</span>
                  <Button size="sm" variant="ghost" className="text-red-600 hover:text-red-700" disabled={String(c.code||'').toUpperCase()===base.toUpperCase()} onClick={()=>onRemoveCurrency(String(c.code||'').toUpperCase())}><Trash2 className="w-4 h-4"/></Button>
                </div>
              ))}
            </div>
          </div>
          <p className="text-xs text-slate-500 sm:col-span-3">Totals are computed from category amounts only (converted to base). Add currencies to see side‑by‑side values.</p>
        </div>
      )}
    </div>
  );
}

function HistoryTab({ data, onDeleteEntry, onDeleteHistoryItem, categories }) {
  const rows = useMemo(() => [...((data.history || []) as HistoryItem[])].sort((a, b) => (b.ts||'').localeCompare(a.ts||'')), [data.history]);
  return (
    <Card className="border-slate-200">
      <CardContent className="p-4">
        <h3 className="font-medium mb-3">History</h3>
        <div className="overflow-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="text-left text-slate-600">
                <th className="py-2 pr-4">Time</th>
                <th className="py-2 pr-4">Event</th>
                <th className="py-2 pr-4">Details</th>
                <th className="py-2 pr-4">Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(h => {
                const dt = h.ts ? new Date(h.ts) : null;
                let details = null;
                if (h.type?.startsWith('entry')) {
                  const cat = categories.find(c => c.id === h.entry?.categoryId);
                  const label = cat?.name || '?';
                  details = <span>{label} — {formatAmount(cat?.currency || data.baseCurrency, h.entry?.amount || 0)}</span>;
                } else if (h.type?.startsWith('category')) {
                  details = <span>{h.category?.name}</span>;
                } else {
                  details = <span>—</span>;
                }
                return (
                  <tr key={h.id} className="border-t">
                    <td className="py-2 pr-4 whitespace-nowrap">{dt ? dt.toLocaleString() : '—'}</td>
                    <td className="py-2 pr-4">{h.type}</td>
                    <td className="py-2 pr-4">{details}</td>
                    <td className="py-2 pr-4 flex gap-2">
                      {h.type === 'entry:add' && (
                        <Button size="sm" variant="outline" onClick={()=> onDeleteEntry(h.entry?.id)}>Delete entry</Button>
                      )}
                      <Button size="sm" variant="ghost" className="text-red-600" onClick={()=> onDeleteHistoryItem(h.id)}>Remove log</Button>
                    </td>
                  </tr>
                );
              })}
              {rows.length===0 && <tr><td colSpan={4} className="py-6 text-center text-slate-500">No history yet.</td></tr>}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

function Dashboard({ data, onAddEntry }) {
  const { categories, entries } = data;
  const years = useMemo(()=>{
    const s = new Set(entries.map(e=> new Date(e.dateISO).getFullYear()));
    if (s.size === 0) s.add(new Date().getFullYear());
    return [...s].sort();
  }, [entries]);
  const [year, setYear] = useState(years[years.length-1]);
  const [graphIndex, setGraphIndex] = useState(0); // 0 = line, 1 = pie
  const toggleGraph = () => setGraphIndex(i => (i + 1) % 2);

  useEffect(()=>{ if(years.length) setYear(years[years.length-1]); }, [years.length]);

  const monthly = useMemo(()=>{
    // aggregate per month per category for selected year
    const months = Array.from({length:12}, (_,i)=> i);
    const map = {};
    categories.forEach(c=> map[c.id] = months.map(()=>0));
    for (const e of entries) {
      const d = new Date(e.dateISO);
      if (d.getFullYear() !== Number(year)) continue;
      const m = d.getMonth();
      map[e.categoryId][m] += e.amount;
    }
    // cumulative by month (savings line)
    for (const cid of Object.keys(map)) {
      let run = 0; for (let i=0;i<12;i++){ run += map[cid][i]; map[cid][i] = run; }
    }
    // convert to recharts data
    const monthNames = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    return months.map((m,i)=>{
      const row = { month: monthNames[i] };
      categories.forEach(c=> row[c.name] = map[c.id][i]);
      return row;
    });
  }, [categories, entries, year]);

  const pieData = useMemo(()=>{
  const base = (data.baseCurrency||'BDT').toUpperCase();
  const rates = new Map<string, number>((data.currencies||[]).map((c:Currency) => [String(c.code||'').toUpperCase(), Number(c.rate)||0]));
  const getRate = (code?:string): number => {
    const cc = (code||base).toUpperCase();
    if (cc===base) return 1;
    return (rates.get(cc) ?? 1);
  };
  return categories.map((c:Category) => ({
    name: c.name,
    value: (Number(c.amount)||0) / getRate(c.currency)
  }));
}, [categories, data.currencies, data.baseCurrency]);


  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-lg font-semibold">Savings Overview</h2>
        <div className="flex items-center gap-3">
          <div className="w-36">
            <Select value={String(year)} onValueChange={(v)=>setYear(Number(v))}>
              <SelectTrigger><SelectValue placeholder="Year"/></SelectTrigger>
              <SelectContent>
                {years.map(y=> <SelectItem key={y} value={String(y)}>{y}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="icon" onClick={toggleGraph}><ChevronLeft className="w-4 h-4"/></Button>
            <div className="text-sm w-28 text-center">{graphIndex===0 ? 'Line' : 'Assets Pie'}</div>
            <Button variant="outline" size="icon" onClick={toggleGraph}><ChevronRight className="w-4 h-4"/></Button>
          </div>
        </div>
      </div>

      <Card className="border-slate-200">
        <CardContent className="p-4 h-[360px]">
          <ResponsiveContainer width="100%" height="100%">
            {graphIndex === 0 ? (
              <LineChart data={monthly} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                <XAxis dataKey="month"/>
                <YAxis/>
                <Tooltip/>
                <Legend/>
                {categories.map((c)=> (
                  <Line key={c.id} type="monotone" dataKey={c.name} strokeWidth={2} dot={false} isAnimationActive={false} />
                ))}
              </LineChart>
            ) : (
              <PieChart>
                <Tooltip formatter={(value, name) => {
                  const total = pieData.reduce((s,d)=> s + d.value, 0) || 1;
                  const pct = ((value / total) * 100).toFixed(1) + '%';
                  return [`${Number(value).toLocaleString()} (${pct})`, name];
                }} />
                <Legend/>
                <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={120} label={({ name, percent }) => `${name}: ${(percent*100).toFixed(1)}%`} />
              </PieChart>
            )}
          </ResponsiveContainer>
        </CardContent>
      </Card>

      <Card className="border-slate-200">
        <CardContent className="p-4 space-y-3">
          <h3 className="font-medium">Add Savings Entry</h3>
          <AddEntry categories={categories} onAdd={onAddEntry} />
        </CardContent>
      </Card>
    </div>
  );
}

// ==========================
// Auth & Setup Screens
// ==========================
function SetupScreen({ onComplete }) {
  const [firstName, setFirstName] = useState('Arif');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [qas, setQas] = useState([
    { q: 'Your first school?', a: '' },
    { q: 'Mother\'s maiden name?', a: '' },
    { q: 'Favorite book?', a: '' },
    { q: 'City you were born?', a: '' },
    { q: 'First pet\'s name?', a: '' },
  ]);
  const [err, setErr] = useState('');

  const updateQA = (i, field, value) => {
    setQas(prev => prev.map((qa, idx)=> idx===i ? { ...qa, [field]: value } : qa));
  };

  async function handleSetup() {
    setErr('');
    if (!firstName || !password || !confirm) { setErr('Please fill all required fields.'); return; }
    if (password !== confirm) { setErr('Passwords do not match.'); return; }
    if (qas.some(qa => !qa.q || !qa.a)) { setErr('Please provide all 5 questions and answers.'); return; }

    // Derive verifier & AES key
    const saltPwd = randBytes(16);
    const verifierBits = await pbkdf2(password, saltPwd, 210000, 32);
    const verifierHex = toHex(verifierBits);

    const saltEnc = randBytes(16);
    const aesKey = await getAesKeyFromPassword(password, saltEnc);

    // Hash Q&A
    const qasHashed = [];
    for (const qa of qas) {
      const salt = randBytes(16);
      const hash = await hashAnswer(qa.a, salt);
      qasHashed.push({ q: qa.q, saltB64: b64encode(salt), hashB64: hash });
    }

    const initialData = { categories: [], entries: [], currencies: [{ code: "BDT", rate: 1 }], baseCurrency: "BDT", history: [] };
    const enc = await encryptJson(initialData, aesKey);

    const state = {
      version: 1,
      user: { firstName },
      auth: { saltPwdHex: toHex(saltPwd), verifierHex, qas: qasHashed },
      enc: { saltEncHex: toHex(saltEnc), ivB64: enc.iv, ciphertextB64: enc.ciphertext }
    };
    saveState(state);
    onComplete();
  }

  return (
    <div className="max-w-3xl mx-auto p-6 space-y-5">
      <div className="text-center space-y-2">
        <h1 className="text-2xl font-bold">Personal Finance (E2EE) — First‑time Setup</h1>
        <p className="text-slate-600">Create your password and 5 security questions. Your data is encrypted locally with your password.</p>
      </div>

      <Card>
        <CardContent className="p-6 space-y-4">
          <div className="grid sm:grid-cols-2 gap-3">
            <div>
              <label className="text-sm">First Name</label>
              <Input value={firstName} onChange={(e)=>setFirstName(e.target.value)} placeholder="e.g., Arif"/>
            </div>
            <div>
              <label className="text-sm">Password</label>
              <Input type="password" value={password} onChange={(e)=>setPassword(e.target.value)} />
            </div>
            <div className="sm:col-start-2">
              <label className="text-sm">Confirm Password</label>
              <Input type="password" value={confirm} onChange={(e)=>setConfirm(e.target.value)} />
            </div>
          </div>

          <div className="pt-2">
            <h3 className="font-medium mb-2">Security Questions (all 5 required)</h3>
            <div className="grid gap-3">
              {qas.map((qa,i)=> (
                <div key={i} className="grid sm:grid-cols-2 gap-2">
                  <Input value={qa.q} onChange={(e)=>updateQA(i,'q',e.target.value)} placeholder={`Question ${i+1}`} />
                  <Input type="password" value={qa.a} onChange={(e)=>updateQA(i,'a',e.target.value)} placeholder="Answer"/>
                </div>
              ))}
            </div>
          </div>

          {err && <div className="text-red-600 text-sm">{err}</div>}

          <div className="flex justify-end">
            <Button className="gap-2" onClick={handleSetup}><ShieldCheck className="w-4 h-4"/>Finish Setup</Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function LoginScreen({ onUnlock, onReset }) {
  const [password, setPassword] = useState('');
  const [step, setStep] = useState(1); // 1=password, 2=questions
  const [answers, setAnswers] = useState({});
  const [err, setErr] = useState('');

  const state = loadState();
  const qas = state?.auth?.qas || [];

  async function verifyPassword() {
    setErr('');
    try {
      const saltPwd = fromHex(state.auth.saltPwdHex);
      const verifierBits = await pbkdf2(password, saltPwd, 210000, 32);
      const verifierHex = toHex(verifierBits);
      if (verifierHex !== state.auth.verifierHex) {
        setErr('Invalid password.');
        return;
      }
      setStep(2);
    } catch (e) {
      setErr('Something went wrong.');
    }
  }

  async function verifyQuestions() {
    setErr('');
    try {
      for (const qa of qas) {
        const salt = b64decode(qa.saltB64);
        const given = await hashAnswer(answers[qa.q] || '', salt);
        if (given !== qa.hashB64) { setErr('One or more answers are incorrect.'); return; }
      }
      // reconstruct AES key and decrypt
      const key = await getAesKeyFromPassword(password, fromHex(state.enc.saltEncHex));
      const data = await decryptJson(state.enc.ciphertextB64, state.enc.ivB64, key);
      onUnlock({ key, data });
    } catch (e) {
      console.error(e);
      setErr('Failed to decrypt.');
    }
  }

  return (
    <div className="max-w-md mx-auto p-6 space-y-5">
      <div className="text-center space-y-2">
        <h1 className="text-2xl font-bold">Personal Finance — Secure Login</h1>
        <p className="text-slate-600">Your vault is protected with a password and 5 security questions.</p>
      </div>

      <Card>
        <CardContent className="p-6 space-y-4">
          {step===1 && (
            <>
              <div>
                <label className="text-sm">Password</label>
                <Input type="password" value={password} onChange={(e)=>setPassword(e.target.value)} />
              </div>
              {err && <div className="text-red-600 text-sm">{err}</div>}
              <div className="flex justify-between">
                <Button onClick={verifyPassword} className="gap-2"><LockKeyhole className="w-4 h-4"/>Continue</Button>
                <Button variant="outline" onClick={onReset}>Reset / Re‑setup</Button>
              </div>
            </>
          )}

          {step===2 && (
            <>
              <div className="space-y-3">
                {qas.map((qa,i)=> (
                  <div key={i}>
                    <label className="text-sm">{qa.q}</label>
                    <Input type="password" value={answers[qa.q]||''} onChange={(e)=>setAnswers(a=>({...a,[qa.q]: e.target.value}))} />
                  </div>
                ))}
              </div>
              {err && <div className="text-red-600 text-sm">{err}</div>}
              <div className="flex justify-between">
                <Button onClick={()=>setStep(1)} variant="outline">Back</Button>
                <Button onClick={verifyQuestions} className="gap-2"><ShieldCheck className="w-4 h-4"/>Unlock</Button>
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ==========================
// Main App
// ==========================
export default function App() {
  const [boot, setBoot] = useState('loading'); // loading | setup | login | app
  const [firstName, setFirstName] = useState('');
  const [aesKey, setAesKey] = useState(null);
  const [data, setData] = useState({ categories: [], entries: [], currencies: [{ code: "BDT", rate: 1 }], baseCurrency: "BDT", history: [] });

  useEffect(()=>{
    if (typeof window === 'undefined') return;
    const state = loadState();
    if (!state) { setBoot('setup'); return; }
    setFirstName(state.user?.firstName || '');
    setBoot('login');
  }, []);

  async function persist(newData) {
    const state = loadState();
    if (!state || !aesKey) return;
    const enc = await encryptJson(newData, aesKey);
    state.enc.ivB64 = enc.iv;
    state.enc.ciphertextB64 = enc.ciphertext;
    saveState(state);
  }

  function onAddCategory(cat) {
    setData(prev=>{
      const nd = { ...prev, categories: [...prev.categories, cat] };
      persist(nd);
      return nd;
    });
  }
  function onAddEntry(entry) {
    setData(prev=>{
      const nd = { ...prev, entries: [...prev.entries, entry], history: [ ...(prev.history||[]), { id: newId(), ts: new Date().toISOString(), type: 'entry:add', entry } ] };
      persist(nd);
      return nd;
    });
  }

  function onDeleteCategory(catId) {
    const catNow = data.categories.find(c=>c.id===catId);
    if (!catNow) return;
    const count = (data.entries||[]).filter(e=>e.categoryId===catId).length;
    const ok = confirm(`Delete category "${catNow.name}" and ${count} linked entries?`);
    if (!ok) return;
    setData(prev => {
      const cat = prev.categories.find(c=>c.id===catId);
      if (!cat) return prev;
      const entriesLeft = (prev.entries||[]).filter(e=>e.categoryId!==catId);
      const nd = { ...prev, categories: prev.categories.filter(c=>c.id!==catId), entries: entriesLeft, history: [ ...(prev.history||[]), { id: newId(), ts: new Date().toISOString(), type: 'category:delete', category: cat, removedEntriesCount: (prev.entries||[]).length - entriesLeft.length } ] };
      persist(nd);
      return nd;
    });
  }

  function onUnlock({ key, data }) {
    setAesKey(key);
    const state = loadState();
    setFirstName(state?.user?.firstName || '');
    const normalized = { baseCurrency: 'BDT', currencies: [{ code: 'BDT', rate: 1 }], history: [], ...data };
    setData(normalized);
    setBoot('app');
    persist(normalized);
  }

  function onReset() {
    if (confirm('This will erase local encrypted data and setup. Continue?')) {
      clearState();
      setBoot('setup');
    }
  }

  function onLogout() {
    setAesKey(null);
    setData({ categories: [], entries: [], currencies: [{ code: 'BDT', rate: 1 }], baseCurrency: 'BDT', history: [] });
    setBoot('login');
  }

  function onAddCurrency({ code, rate }) {
    setData(prev => {
      const existing = prev.currencies || [];
      const next = [...existing.filter(c => (c.code||'').toUpperCase() !== (code||'').toUpperCase()), { code: (code||'').toUpperCase(), rate: Number(rate)||0 }];
      const nd = { ...prev, currencies: next };
      persist(nd);
      return nd;
    });
  }
  function onSetBaseCurrency(code) {
    setData(prev => {
      const nd = { ...prev, baseCurrency: (code||'').toUpperCase() };
      persist(nd);
      return nd;
    });
  }

  function onRemoveCurrency(code) {
    setData(prev => {
      const up = String(code||'').toUpperCase();
      const base = String(prev.baseCurrency||'BDT').toUpperCase();
      if (up === base) { alert('Cannot remove base currency.'); return prev; }
      const inUse = (prev.categories||[]).some(cat => String(cat.currency||base).toUpperCase() === up);
      if (inUse) { alert('Cannot remove a currency that is used by a category. Change those categories first.'); return prev; }
      const next = (prev.currencies||[]).filter(c => String(c.code||'').toUpperCase() !== up);
      const nd = { ...prev, currencies: next.length ? next : [{ code: base, rate: 1 }] };
      persist(nd);
      return nd;
    });
  }

  function onDeleteEntry(entryId) {
    setData(prev => {
      const target = (prev.entries||[]).find(x=>x.id===entryId);
      const nd = { ...prev, entries: (prev.entries||[]).filter(x=>x.id!==entryId), history: [ ...(prev.history||[]), { id: newId(), ts: new Date().toISOString(), type: 'entry:delete', entry: target } ] };
      persist(nd);
      return nd;
    });
  }

  function onDeleteHistoryItem(historyId) {
    setData(prev => {
      const nd = { ...prev, history: (prev.history||[]).filter(h=>h.id!==historyId) };
      persist(nd);
      return nd;
    });
  }

  if (boot === 'loading') return null;
  if (boot === 'setup') return <SetupScreen onComplete={()=>setBoot('login')} />;
  if (boot === 'login') return <LoginScreen onUnlock={onUnlock} onReset={onReset} />;

  // App shell
  return (
    <div className="min-h-screen bg-slate-50 p-3 sm:p-6">
      <div className="mx-auto max-w-6xl bg-white/60 backdrop-blur rounded-2xl shadow-sm border">
        <Header firstName={firstName} onLogout={onLogout} />
        <TotalsBar data={data} onAddCurrency={onAddCurrency} onSetBaseCurrency={onSetBaseCurrency} onRemoveCurrency={onRemoveCurrency} />
        <div className="flex flex-col sm:flex-row">
          <Sidebar onAddCategory={onAddCategory} categories={data.categories} currencies={data.currencies} baseCurrency={data.baseCurrency} onDeleteCategory={onDeleteCategory} />
          <main className="flex-1 p-4 sm:p-6 space-y-4">
            <Tabs defaultValue="dashboard">
              <TabsList>
                <TabsTrigger value="dashboard">Dashboard</TabsTrigger>
                <TabsTrigger value="data">Data</TabsTrigger>
                <TabsTrigger value="history">History</TabsTrigger>
                <TabsTrigger value="settings">Settings</TabsTrigger>
              </TabsList>

              <TabsContent value="dashboard">
                <Dashboard data={data} onAddEntry={onAddEntry} />
              </TabsContent>

              <TabsContent value="data">
                <Card className="border-slate-200">
                  <CardContent className="p-4">
                    <h3 className="font-medium mb-3">Entries</h3>
                    <div className="overflow-auto">
                      <table className="min-w-full text-sm">
                        <thead>
                          <tr className="text-left text-slate-600">
                            <th className="py-2 pr-4">Date</th>
                            <th className="py-2 pr-4">Category</th>
                            <th className="py-2 pr-4">Amount</th>
                            <th className="py-2 pr-4">Actions</th>
                          </tr>
                        </thead>
                        <tbody>
                          {(data.entries as Entry[]).map((e) => {
                            const c = data.categories.find(c=>c.id===e.categoryId);
                            return (
                              <tr key={e.id} className="border-t">
                                <td className="py-2 pr-4">{new Date(e.dateISO).toLocaleDateString()}</td>
                                <td className="py-2 pr-4">{c?.name||'?'}</td>
                                <td className="py-2 pr-4">{formatAmount(c?.currency || data.baseCurrency, e.amount)}</td>
                                <td className="py-2 pr-4">
                                  <Button variant="ghost" size="sm" onClick={()=> onDeleteEntry(e.id)} className="text-red-600 hover:text-red-700"><Trash2 className="w-4 h-4"/></Button>
                                </td>
                              </tr>
                            );
                          })}
                          {data.entries.length===0 && (
                            <tr><td colSpan={4} className="py-6 text-center text-slate-500">No entries yet. Add some from the Dashboard.</td></tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="history">
                <HistoryTab data={data} categories={data.categories} onDeleteEntry={onDeleteEntry} onDeleteHistoryItem={onDeleteHistoryItem} />
              </TabsContent>

              <TabsContent value="settings">
                <Card className="border-slate-200">
                  <CardContent className="p-4 space-y-3">
                    <h3 className="font-medium">Vault Controls</h3>
                    <div className="flex flex-wrap gap-2">
                      <Button variant="outline" onClick={onReset}>Erase & Re‑setup</Button>
                    </div>
                    <p className="text-sm text-slate-600">This version stores everything locally, encrypted with AES‑GCM using a key derived from your password (PBKDF2‑SHA256, 210k rounds). Keep your password safe — there is no recovery.</p>
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          </main>
        </div>
      </div>
    </div>
  );
}
