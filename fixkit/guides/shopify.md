# Install on Shopify

## 1. Schema + social tags (10 min)
- Go to **Online Store → Themes → … → Edit code**.
- Open `layout/theme.liquid`, find `</head>`.
- Paste the contents of `schema-jsonld.html` just **before** `</head>`.
- Paste `og-tags.html` there too (Shopify already outputs some OG tags;
  yours will supplement the description/image).
- Upload your social image: **Content → Files**, then use that URL in place of
  `/og-image.jpg`.
- Save.

## 2. llms.txt + robots.txt
- **robots.txt**: Shopify generates it. Go to **Online Store → Themes → Edit code →
  Templates → robots.txt.liquid** and merge the AI-friendly lines from your kit.
- **llms.txt**: Shopify can't serve arbitrary root files — skip it, it's a 5-point
  hedge. Your schema markup carries the weight.
- **Sitemap**: automatic at `yoursite.com/sitemap.xml`. No action needed.

## 3. Ordering
You already have checkout — that's your action surface. Make sure the cart and
product pages are reachable without login so agents can complete purchases.
