// Dutch (Nederlands). Vector codes such as AV:N stay as they are; only names and texts are translated.
// The calls below are marked pure so bundlers drop this catalog from apps that don't import it.
import type { CvssMessages, MetricNames } from '../messages';

const list = (items: string[]) => items.join(', ');

type Names = [name: string, values: Record<string, string>];

/** Adds the modified (M-prefixed) environmental metrics for the given base metrics. */
function withModified(base: Record<string, Names>, keys: string[], extra: Record<string, Record<string, string>> = {}) {
  const out: MetricNames = {};
  for (const [key, [name, values]] of Object.entries(base)) out[key] = { name, values };
  for (const key of keys) {
    const [name, values] = base[key];
    out[`M${key}`] = {
      name: `Aangepaste ${name.charAt(0).toLowerCase()}${name.slice(1)}`,
      values: { ...values, ...extra[key] },
    };
  }
  return out;
}

const NLH = { N: 'Geen', L: 'Laag', H: 'Hoog' };
const LMH = { L: 'Laag', M: 'Gemiddeld', H: 'Hoog' };
const AV = { N: 'Netwerk', A: 'Aangrenzend', L: 'Lokaal', P: 'Fysiek' };

const v2: MetricNames = {
  AV: { name: 'Toegangsvector', values: { L: 'Lokaal', A: 'Aangrenzend netwerk', N: 'Netwerk' } },
  AC: { name: 'Toegangscomplexiteit', values: { H: 'Hoog', M: 'Gemiddeld', L: 'Laag' } },
  Au: { name: 'Authenticatie', values: { M: 'Meervoudig', S: 'Enkelvoudig', N: 'Geen' } },
  C: { name: 'Impact op vertrouwelijkheid', values: { N: 'Geen', P: 'Gedeeltelijk', C: 'Volledig' } },
  I: { name: 'Impact op integriteit', values: { N: 'Geen', P: 'Gedeeltelijk', C: 'Volledig' } },
  A: { name: 'Impact op beschikbaarheid', values: { N: 'Geen', P: 'Gedeeltelijk', C: 'Volledig' } },
  E: {
    name: 'Exploiteerbaarheid',
    values: { U: 'Onbewezen', POC: 'Proof-of-concept', F: 'Functioneel', H: 'Hoog' },
  },
  RL: {
    name: 'Herstelniveau',
    values: { OF: 'Officiële oplossing', TF: 'Tijdelijke oplossing', W: 'Workaround', U: 'Niet beschikbaar' },
  },
  RC: { name: 'Betrouwbaarheid van de melding', values: { UC: 'Onbevestigd', UR: 'Niet gestaafd', C: 'Bevestigd' } },
  CDP: {
    name: 'Potentiële nevenschade',
    values: { N: 'Geen', L: 'Laag', LM: 'Laag-gemiddeld', MH: 'Gemiddeld-hoog', H: 'Hoog' },
  },
  TD: { name: 'Verspreiding van doelen', values: { N: 'Geen', L: 'Laag', M: 'Gemiddeld', H: 'Hoog' } },
  CR: { name: 'Vertrouwelijkheidseis', values: LMH },
  IR: { name: 'Integriteitseis', values: LMH },
  AR: { name: 'Beschikbaarheidseis', values: LMH },
};

const v3 = /* @__PURE__ */ withModified(
  {
    AV: ['Aanvalsvector', AV],
    AC: ['Aanvalscomplexiteit', { L: 'Laag', H: 'Hoog' }],
    PR: ['Vereiste rechten', NLH],
    UI: ['Gebruikersinteractie', { N: 'Geen', R: 'Vereist' }],
    S: ['Scope', { U: 'Ongewijzigd', C: 'Gewijzigd' }],
    C: ['Vertrouwelijkheid', NLH],
    I: ['Integriteit', NLH],
    A: ['Beschikbaarheid', NLH],
    E: ['Volwassenheid van exploitcode', { U: 'Onbewezen', P: 'Proof-of-concept', F: 'Functioneel', H: 'Hoog' }],
    RL: [
      'Herstelniveau',
      { O: 'Officiële oplossing', T: 'Tijdelijke oplossing', W: 'Workaround', U: 'Niet beschikbaar' },
    ],
    RC: ['Betrouwbaarheid van de melding', { U: 'Onbekend', R: 'Redelijk', C: 'Bevestigd' }],
    CR: ['Vertrouwelijkheidseis', LMH],
    IR: ['Integriteitseis', LMH],
    AR: ['Beschikbaarheidseis', LMH],
  },
  ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'],
);

const HLN = { H: 'Hoog', L: 'Laag', N: 'Geen' };

const v4 = /* @__PURE__ */ withModified(
  {
    AV: ['Aanvalsvector', AV],
    AC: ['Aanvalscomplexiteit', { L: 'Laag', H: 'Hoog' }],
    AT: ['Aanvalsvereisten', { N: 'Geen', P: 'Aanwezig' }],
    PR: ['Vereiste rechten', NLH],
    UI: ['Gebruikersinteractie', { N: 'Geen', P: 'Passief', A: 'Actief' }],
    VC: ['Vertrouwelijkheid van het kwetsbare systeem', HLN],
    VI: ['Integriteit van het kwetsbare systeem', HLN],
    VA: ['Beschikbaarheid van het kwetsbare systeem', HLN],
    SC: ['Vertrouwelijkheid van volgende systemen', HLN],
    SI: ['Integriteit van volgende systemen', HLN],
    SA: ['Beschikbaarheid van volgende systemen', HLN],
    E: ['Volwassenheid van exploits', { A: 'Aangevallen', P: 'Proof-of-concept', U: 'Niet gemeld' }],
    CR: ['Vertrouwelijkheidseis', LMH],
    IR: ['Integriteitseis', LMH],
    AR: ['Beschikbaarheidseis', LMH],
    S: ['Veiligheid', { N: 'Verwaarloosbaar', P: 'Aanwezig' }],
    AU: ['Automatiseerbaar', { N: 'Nee', Y: 'Ja' }],
    R: ['Herstel', { A: 'Automatisch', U: 'Gebruiker', I: 'Onherstelbaar' }],
    V: ['Waardedichtheid', { D: 'Diffuus', C: 'Geconcentreerd' }],
    RE: ['Inspanning voor de respons', { L: 'Laag', M: 'Gemiddeld', H: 'Hoog' }],
    U: ['Urgentie volgens de leverancier', { Clear: 'Helder', Green: 'Groen', Amber: 'Amber', Red: 'Rood' }],
  },
  ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'],
  { SI: { S: 'Veiligheid' }, SA: { S: 'Veiligheid' } },
);

/** Dutch. */
export const nl: CvssMessages = {
  locale: 'nl',
  severity: { None: 'Geen', Low: 'Laag', Medium: 'Gemiddeld', High: 'Hoog', Critical: 'Kritiek' },
  groups: {
    base: 'Basis',
    temporal: 'Tijdelijk',
    threat: 'Dreiging',
    environmental: 'Omgeving',
    supplemental: 'Aanvullend',
  },
  notDefined: 'Niet gedefinieerd',
  metrics: { '2.0': v2, '3.x': v3, '4.0': v4 },
  issues: {
    EMPTY: () => 'Voer een CVSS-vector in.',
    UNKNOWN_PREFIX: (p) => `"${p.text}" is geen ondersteunde CVSS-versie.`,
    NONSTANDARD_PREFIX: () => 'CVSS 2.0-vectoren hebben geen prefix. Bij het normaliseren wordt de prefix verwijderd.',
    MISSING_PREFIX: (p) =>
      `De vector heeft geen prefix "${p.prefix}/".${p.strict ? '' : ' Bij het normaliseren wordt die toegevoegd.'}`,
    AMBIGUOUS_VERSION: () =>
      'Dit lijkt een CVSS 3.x-vector zonder prefix. Voeg "CVSS:3.0/" of "CVSS:3.1/" toe, of stel de versie in.',
    UNDETECTABLE_VERSION: () =>
      'De CVSS-versie is niet te bepalen. Voeg een prefix toe, zoals "CVSS:3.1/", of stel de versie in.',
    VERSION_MISMATCH: (p) =>
      p.source === 'base'
        ? `De vector is CVSS ${p.found}, maar de basisvector is CVSS ${p.expected}.`
        : `De vector is CVSS ${p.found}, maar CVSS ${p.expected} is vereist.`,
    MALFORMED_SEGMENT: (p) =>
      p.raw === '' ? 'De vector bevat een leeg deel ("//").' : `"${p.raw}" is geen paar "metriek:waarde".`,
    UNKNOWN_METRIC: (p) => `"${p.key}" is geen metriek van CVSS ${p.version}.`,
    INVALID_VALUE: (p, f) =>
      `"${p.value}" is geen geldige waarde voor ${p.key} (${f.metric(p.version, p.key)}). Geldige waarden: ${list(p.valid)}.`,
    DUPLICATE_METRIC: (p) => `${p.key} komt meer dan één keer voor.`,
    MISSING_METRIC: (p, f) => `${p.key} (${f.metric(p.version, p.key)}) ontbreekt.`,
    METRIC_ORDER: (p) =>
      p.strict
        ? `De metrieken staan niet in de volgorde van de CVSS ${p.version}-specificatie.`
        : 'De metrieken staan niet in de standaardvolgorde. Bij het normaliseren worden ze gesorteerd.',
    BASE_METRIC_IN_OVERLAY: (p) => `"${p.key}" is een basismetriek. Basismetrieken komen uit de basisvector.`,
    INVALID_BASE_VECTOR: (p, f) =>
      p.issues === null
        ? 'De basisvector is ongeldig, dus de lagen kunnen niet worden gecombineerd.'
        : `De basisvector is ongeldig: ${p.issues.map(f.issue).join(' ') || 'onbekende versie.'}`,
    METRIC_CONFLICT: (p, f) =>
      p.kind === 'requirements'
        ? `${f.layer(p.layer)} stelt ${p.key} zowel in de vector als via de beveiligingseisen in.`
        : `${p.key} heeft verschillende waarden: ${list(p.values.map((v) => `${f.layer(v.layer)} ${p.key}:${v.value}`))}.`,
    METRIC_NOT_ALLOWED_IN_LAYER: (p, f) =>
      p.kind === 'metric'
        ? `${f.layer(p.layer)} mag ${p.key} niet instellen; deze laag accepteert alleen metrieken uit: ${list(p.allowed.map(f.group))}.`
        : `${f.layer(p.layer)} heeft beveiligingseisen, maar accepteert geen omgevingsmetrieken.`,
    MISSING_LAYER_VECTOR: (p, f) =>
      `${f.layer(p.layer)} heeft geen metrieken voor CVSS ${p.family}${p.hasRequirements ? '; alleen de beveiligingseisen tellen mee' : ''}.`,
    INVALID_REQUIREMENTS: (p, f) => `${f.layer(p.layer)} heeft ongeldige beveiligingseisen. Gebruik L, M, H of X.`,
    DUPLICATE_LAYER_ID: (p) =>
      p.reserved
        ? '"base" is gereserveerd voor de basisvector.'
        : `Laag-ID "${p.layer}" wordt meer dan één keer gebruikt.`,
    INVALID_CONFLICT_RESOLUTION: (p) =>
      `De conflictregel gaf "${p.picked}" terug voor ${p.key}, maar geen enkele laag stelt die waarde in.`,
    TOO_LONG: (p, f) => `De vector is ${f.number(p.length)} tekens lang; het maximum is ${f.number(p.max)}.`,
    TOO_MANY_ISSUES: (p, f) => `…en nog ${f.number(p.count)} ${p.count === 1 ? 'probleem' : 'problemen'}.`,
  },
  ui: {
    vectorLabel: 'CVSS-vector',
    overlayLabel: 'Tijdelijke en omgevingsmetrieken',
    thisInput: 'Deze invoer',
    baseVector: 'Basisvector',
    version: 'Versie',
    versionUnknown: 'Versie onbekend',
    versionDetected: 'herkend',
    versionRequired: 'vereist',
    versionFromBase: 'uit basisvector',
    alsoApplied: 'Ook toegepast:',
    combined: 'Gecombineerd',
    error: 'Fout',
    note: 'Let op',
    goToPosition: (n) => `Ga naar positie ${n}`,
    position: (n) => `(positie ${n})`,
    treatAs: (v) => `Behandelen als CVSS ${v}`,
    pickerUnavailable: 'Voer een geldige vector in of stel een versie in om de metriekkiezer te gebruiken.',
    pickerBlocked: 'Los de fouten in de vector op om hem met de kiezer te bewerken.',
    groupFromBase: '(uit basisvector)',
    contextValue: (layer, value, applied) => `${layer}: ${value} (${applied ? 'toegepast' : 'niet toegepast'})`,
    overriddenBy: (layer) => `Overschreven door ${layer}.`,
    conflictsWithLayer: 'Conflicteert met een andere laag.',
    score: 'Score',
    base: 'Basis',
    temporal: 'Tijdelijk',
    environmental: 'Omgeving',
    final: 'Eindscore',
    baseDetail: (impact, exploitability) => `Impact ${impact} · Exploiteerbaarheid ${exploitability}`,
    noTemporal: 'Geen tijdelijke metrieken ingesteld',
    noEnvironmental: 'Geen omgevingsmetrieken ingesteld',
    macroVector: (mv) => `MacroVector ${mv}`,
    statusProblems: (count, capped, first) =>
      `${capped ? `Meer dan ${count} problemen` : `${count} ${count === 1 ? 'probleem' : 'problemen'}`}. ${first}`,
    statusScore: (name, score, severity) => `${name} ${score} ${severity}`,
    statusFinal: (score, severity, group) => `Eindscore ${score} ${severity} (${group}).`,
    statusScores: (parts) => `${parts.join(', ')}.`,
    combinedScore: 'Gecombineerde CVSS-score',
    sources: 'Herkomst van de metrieken',
    sourcesMetric: 'Metriek',
    sourcesValue: 'Waarde',
    sourcesSource: 'Bron',
    conflict: 'Conflict',
    overridden: 'Overschreven: ',
    seeErrorAbove: 'Zie de fout hierboven.',
  },
};
