# Graphic Charter: Sanitize (Config Sanitizer)

This document defines the visual identity of Sanitize, a cybersecurity
application focused on masking sensitive data in configuration files.

## Visual Concept

The logo is based on a "Configuration Shield" metaphor:

- Hexagon: structure, robustness, and protection.
- Document: configuration files (YAML, ENV, JSON).
- Redaction: represented by a strong block in the content area.
- Validation: a success badge confirms the file is safe to share.

## Technical Specifications

### Color Palette (HEX)

- Primary Dark: `#1A2B42`
- Redaction: `#EF4444`
- Success: `#2ECC71`
- Neutral: `#94A3B8`
- Base: `#F5F5F5`

### Clear Space

A 10% exclusion zone around the full logo width should be kept.

## SVG Sources (Copy/Paste Ready)

### 1. Dark Variant (Primary)

Optimized for dark themes and headers.

```xml
<svg width="512" height="512" viewBox="0 0 512 512" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M256 40L446.526 150V362L256 472L65.4745 362V150L256 40Z" fill="#1A2B42"/>
  <rect x="160" y="140" width="192" height="232" rx="8" fill="#F5F5F5"/>
  <path d="M352 180L312 140H344C348.418 140 352 143.582 352 148V180Z" fill="#D1D5DB"/>
  <rect x="184" y="180" width="100" height="12" rx="2" fill="#94A3B8"/>
  <rect x="184" y="210" width="144" height="12" rx="2" fill="#94A3B8"/>
  <rect x="184" y="240" width="120" height="18" rx="4" fill="#EF4444"/>
  <rect x="184" y="280" width="144" height="12" rx="2" fill="#94A3B8"/>
  <circle cx="320" cy="340" r="30" fill="#2ECC71"/>
  <path d="M310 340L317 347L332 332" stroke="white" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
```

### 2. Light Variant

For white backgrounds, printed docs, and light interfaces.

```xml
<svg width="512" height="512" viewBox="0 0 512 512" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M256 50L437.897 155V357L256 462L74.1026 357V155L256 50Z" stroke="#1A2B42" stroke-width="20" stroke-linejoin="round"/>
  <rect x="160" y="140" width="192" height="232" rx="8" fill="#FFFFFF" stroke="#D1D5DB" stroke-width="2"/>
  <rect x="184" y="180" width="100" height="10" rx="2" fill="#94A3B8"/>
  <rect x="184" y="210" width="144" height="10" rx="2" fill="#94A3B8"/>
  <rect x="184" y="240" width="120" height="20" rx="4" fill="#EF4444"/>
  <circle cx="330" cy="340" r="25" fill="#2ECC71"/>
  <path d="M322 340L327 345L338 334" stroke="white" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
```

### 3. Minimal Mono

Recommended for favicons and tiny app/CLI surfaces.

```xml
<svg width="512" height="512" viewBox="0 0 512 512" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M256 40L446.526 150V362L256 472L65.4745 362V150L256 40Z" fill="black"/>
  <rect x="160" y="140" width="192" height="232" rx="4" fill="white"/>
  <rect x="180" y="180" width="152" height="15" rx="2" fill="black"/>
  <rect x="180" y="210" width="152" height="40" rx="2" fill="black"/>
  <rect x="190" y="225" width="60" height="10" fill="white"/>
  <rect x="180" y="265" width="100" height="15" rx="2" fill="black"/>
</svg>
```

## Export Guide

1. Save each SVG block into separate `.svg` files.
2. Export PNG sizes with an SVG toolchain.
3. Prefer the Minimal Mono variant for `.ico` readability at small sizes.
