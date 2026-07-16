lora-pandora/
├── .editorconfig
├── .gitignore
├── .env.example
├── .env.local.example
├── package.json
├── next.config.ts
├── tsconfig.json
├── postcss.config.js
├── tailwind.config.ts
├── components.json
├── sanity.cli.ts
├── README.md
├── docs/
│   ├── architecture.md
│   ├── content-model.md
│   ├── seo-plan.md
│   ├── release-plan.md
│   └── brand-guidelines.md
├── public/
│   ├── images/
│   ├── icons/
│   ├── fonts/
│   └── favicon.ico
├── sanity/
│   ├── env.ts
│   ├── sanity.config.ts
│   ├── schema.json
│   ├── sanity.types.ts
│   └── schemas/
│       ├── documents/
│       │   ├── product.ts
│       │   ├── category.ts
│       │   ├── collection.ts
│       │   ├── heroBanner.ts
│       │   ├── pageBlock.ts
│       │   └── siteSettings.ts
│       ├── objects/
│       │   ├── seo.ts
│       │   ├── cta.ts
│       │   ├── price.ts
│       │   ├── mediaGallery.ts
│       │   └── messengerLink.ts
│       └── index.ts
├── supabase/
│   ├── config.toml
│   ├── migrations/
│   ├── seed.sql
│   └── types.ts
├── src/
│   ├── app/
│   │   ├── (public)/
│   │   │   ├── page.tsx
│   │   │   ├── catalog/
│   │   │   │   ├── page.tsx
│   │   │   │   └── [category]/
│   │   │   │       └── page.tsx
│   │   │   ├── product/
│   │   │   │   └── [slug]/
│   │   │   │       └── page.tsx
│   │   │   ├── collections/
│   │   │   │   └── [slug]/
│   │   │   │       └── page.tsx
│   │   │   ├── about/
│   │   │   │   └── page.tsx
│   │   │   ├── delivery/
│   │   │   │   └── page.tsx
│   │   │   ├── contacts/
│   │   │   │   └── page.tsx
│   │   │   ├── privacy/
│   │   │   │   └── page.tsx
│   │   │   ├── offer/
│   │   │   │   └── page.tsx
│   │   │   └── not-found.tsx
│   │   ├── api/
│   │   │   ├── lead/
│   │   │   │   └── route.ts
│   │   │   ├── contact/
│   │   │   │   └── route.ts
│   │   │   ├── webhook/
│   │   │   │   └── route.ts
│   │   │   └── revalidate/
│   │   │       └── route.ts
│   │   ├── studio/
│   │   │   └── [[...tool]]/
│   │   │       ├── page.tsx
│   │   │       └── layout.tsx
│   │   ├── opengraph-image.tsx
│   │   ├── twitter-image.tsx
│   │   ├── sitemap.ts
│   │   ├── robots.ts
│   │   ├── manifest.ts
│   │   ├── layout.tsx
│   │   ├── not-found.tsx
│   │   └── globals.css
│   ├── shared/
│   │   ├── ui/
│   │   ├── lib/
│   │   ├── hooks/
│   │   ├── config/
│   │   ├── constants/
│   │   ├── types/
│   │   └── utils/
│   ├── entities/
│   │   ├── product/
│   │   │   ├── model/
│   │   │   ├── ui/
│   │   │   └── api/
│   │   ├── category/
│   │   │   ├── model/
│   │   │   ├── ui/
│   │   │   └── api/
│   │   ├── collection/
│   │   │   ├── model/
│   │   │   ├── ui/
│   │   │   └── api/
│   │   └── lead/
│   │       ├── model/
│   │       └── api/
│   ├── features/
│   │   ├── product-filters/
│   │   ├── lead-form/
│   │   ├── contact-form/
│   │   ├── catalog-sorting/
│   │   ├── product-gallery/
│   │   ├── related-products/
│   │   ├── seo-meta/
│   │   └── analytics-events/
│   ├── widgets/
│   │   ├── header/
│   │   ├── footer/
│   │   ├── hero/
│   │   ├── featured-products/
│   │   ├── categories-grid/
│   │   ├── collections-showcase/
│   │   ├── brand-story/
│   │   ├── delivery-info/
│   │   ├── contact-section/
│   │   └── instagram-feed/
│   └── server/
│       ├── sanity/
│       │   ├── client.ts
│       │   ├── queries.ts
│       │   ├── mappers.ts
│       │   └── live.ts
│       ├── supabase/
│       │   ├── client.ts
│       │   ├── admin.ts
│       │   └── repositories/
│       │       └── lead.repository.ts
│       ├── cloudinary/
│       │   ├── client.ts
│       │   └── transforms.ts
│       ├── validation/
│       │   ├── lead.schema.ts
│       │   └── contact.schema.ts
│       └── services/
│           ├── lead.service.ts
│           ├── seo.service.ts
│           ├── analytics.service.ts
│           └── notification.service.ts
├── tests/
│   ├── unit/
│   ├── integration/
│   └── e2e/
└── scripts/
    ├── generate-sitemap.ts
    ├── sanity-typegen.ts
    └── seed-demo-data.ts