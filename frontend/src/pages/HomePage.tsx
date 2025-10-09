// frontend/src/pages/HomePage.tsx
import * as React from "react";
import { motion, useReducedMotion } from "framer-motion";
import {
  Shield,
  Cpu,
  LineChart,
  Rocket,
  Sparkles,
  Menu,
  CheckCircle2,
  ArrowRight,
  PlayCircle,
  Zap,
  ExternalLink
} from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger
} from "@/components/ui/sheet";

type Stat = {
  label: string;
  value: string;
  hint?: string;
  icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
};

type Feature = {
  title: string;
  description: string;
  icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
  points: string[];
};

type Testimonial = {
  name: string;
  role: string;
  quote: string;
};

const motionDefaults = {
  initial: { opacity: 0, y: 16 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, amount: 0.2 },
  transition: { duration: 0.5 }
};

const STATS: Stat[] = [
  { label: "Время отклика", value: "< 50 мс", hint: "P95 на проде", icon: Zap },
  { label: "Аптайм", value: "99.99%", hint: "SLO/месяц", icon: Shield },
  { label: "Обработка", value: "5M+/сутки", hint: "событий", icon: Cpu },
  { label: "Экономия", value: "−37%", hint: "TCO год к году", icon: LineChart }
];

const FEATURES: Feature[] = [
  {
    title: "Zero-Trust безопасность",
    description:
      "Изоляция по умолчанию, чек-поинты доступа, политики на уровне сервисов и UI-гардrails.",
    icon: Shield,
    points: [
      "RBAC/ABAC на уровне компонентов",
      "Слежение за сессиями и токенами",
      "Готовность к аудиту (логирование)"
    ]
  },
  {
    title: "Искусственный интеллект",
    description:
      "Нативная интеграция агентов и пайплайнов — от онбординга до продвинутой аналитики.",
    icon: Cpu,
    points: ["Многоагентные сценарии", "Онлайн-инференс", "Трассировка запросов"]
  },
  {
    title: "Наблюдаемость",
    description:
      "Метрики, логи и трассировки доступны из коробки, с полезными дашбордами.",
    icon: LineChart,
    points: ["Prometheus/Grafana-friendly", "OpenTelemetry трассинг", "SLO панели"]
  },
  {
    title: "Готовность к росту",
    description:
      "Компонентная архитектура и дисциплина по производительности для масштабирования.",
    icon: Rocket,
    points: ["Code-splitting и lazy-routes", "Адаптивные паттерны", "Профайлинг"]
  }
];

const TESTIMONIALS: Testimonial[] = [
  {
    name: "Анна К.",
    role: "Руководитель продукта",
    quote:
      "Домашняя страница стала точкой входа и для клиентов, и для команды — быстро, понятно и без перегруза."
  },
  {
    name: "Илья М.",
    role: "Инженер по надежности",
    quote:
      "Нравится, что доступность и метрики вшиты в UX — меньше ручной рутины и быстрее RCA."
  },
  {
    name: "Дмитрий С.",
    role: "Архитектор",
    quote:
      "Компоненты легко переиспользуются между разделами, анимации не мешают, а подчеркивают смысл."
  }
];

const HeroLogo = React.memo(function HeroLogo() {
  return (
    <svg
      role="img"
      aria-label="Логотип"
      width="48"
      height="48"
      viewBox="0 0 48 48"
      className="shrink-0"
    >
      <defs>
        <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopOpacity="0.9" />
          <stop offset="1" stopOpacity="0.6" />
        </linearGradient>
      </defs>
      <rect x="4" y="4" width="40" height="40" rx="10" fill="url(#g)" />
      <path
        d="M14 30c6-12 14-12 20 0"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
      />
      <circle cx="24" cy="20" r="4" fill="currentColor" />
    </svg>
  );
});

function usePrefersReducedMotion() {
  const reduce = useReducedMotion();
  return reduce;
}

const Container: React.FC<React.PropsWithChildren> = ({ children }) => (
  <div className="mx-auto w-full max-w-7xl px-4 sm:px-6 lg:px-8">{children}</div>
);

const SectionTitle: React.FC<{ title: string; subtitle?: string }> = ({ title, subtitle }) => (
  <div className="max-w-3xl">
    <h2 className="text-2xl md:text-3xl font-semibold tracking-tight">{title}</h2>
    {subtitle ? (
      <p className="mt-2 text-muted-foreground leading-relaxed">{subtitle}</p>
    ) : null}
  </div>
);

const StatCard: React.FC<{ stat: Stat }> = ({ stat }) => {
  const Icon = stat.icon;
  return (
    <Card className="h-full">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{stat.label}</CardTitle>
        <Icon className="h-4 w-4 text-muted-foreground" aria-hidden />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{stat.value}</div>
        {stat.hint && <p className="text-xs text-muted-foreground mt-1">{stat.hint}</p>}
      </CardContent>
    </Card>
  );
};

const FeatureCard: React.FC<{ feature: Feature }> = ({ feature }) => {
  const Icon = feature.icon;
  return (
    <Card className="h-full">
      <CardHeader>
        <div className="flex items-center gap-3">
          <span className="inline-flex h-9 w-9 items-center justify-center rounded-xl bg-muted">
            <Icon className="h-5 w-5" aria-hidden />
          </span>
          <CardTitle className="text-lg">{feature.title}</CardTitle>
        </div>
        <CardDescription className="mt-2">{feature.description}</CardDescription>
      </CardHeader>
      <CardContent className="pt-0">
        <ul className="space-y-2">
          {feature.points.map((p, i) => (
            <li key={i} className="flex items-start gap-3">
              <CheckCircle2 className="h-4 w-4 mt-0.5 text-muted-foreground" aria-hidden />
              <span className="text-sm leading-relaxed">{p}</span>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
};

const TestimonialCard: React.FC<{ t: Testimonial }> = ({ t }) => (
  <Card className="h-full">
    <CardHeader>
      <CardTitle className="text-base">“{t.quote}”</CardTitle>
      <CardDescription className="mt-1">
        {t.name} · {t.role}
      </CardDescription>
    </CardHeader>
  </Card>
);

const NewsletterForm: React.FC = () => {
  const [value, setValue] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [done, setDone] = React.useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!value) return;
    setLoading(true);
    // Имитация запроса; интеграция с реальным API — в обработчике действия/сервисе.
    await new Promise((r) => setTimeout(r, 700));
    setLoading(false);
    setDone(true);
  }

  return (
    <form onSubmit={onSubmit} className="w-full">
      <div className="flex flex-col sm:flex-row gap-3">
        <Input
          aria-label="Ваш email"
          type="email"
          placeholder="name@company.com"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          required
          className="h-11"
        />
        <Button type="submit" className="h-11" disabled={loading || done}>
          {done ? "Готово" : loading ? "Отправка..." : "Подписаться"}
        </Button>
      </div>
      <p className="text-xs text-muted-foreground mt-2">
        Подписываясь, вы соглашаетесь с политикой конфиденциальности.
      </p>
    </form>
  );
};

const DemoVideoButton: React.FC = () => (
  <Button variant="secondary" className="h-11" asChild>
    <a href="#" aria-label="Смотреть демо" onClick={(e) => e.preventDefault()}>
      <PlayCircle className="mr-2 h-4 w-4" aria-hidden /> Смотреть демо
    </a>
  </Button>
);

const NavBar: React.FC = () => {
  return (
    <header className="sticky top-0 z-40 w-full border-b bg-background/80 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <Container>
        <div className="flex h-14 items-center justify-between">
          <a href="/" className="flex items-center gap-3" aria-label="На главную">
            <HeroLogo />
            <span className="sr-only">Главная</span>
            <div className="flex flex-col">
              <span className="text-sm font-semibold tracking-tight">Aethernova</span>
              <span className="text-xs text-muted-foreground">Next-gen AI/Web3 Suite</span>
            </div>
          </a>

          <nav className="hidden md:flex items-center gap-6">
            <a className="text-sm text-muted-foreground hover:text-foreground" href="#features">
              Возможности
            </a>
            <a className="text-sm text-muted-foreground hover:text-foreground" href="#stats">
              Метрики
            </a>
            <a className="text-sm text-muted-foreground hover:text-foreground" href="#pricing">
              Тарифы
            </a>
            <a className="text-sm text-muted-foreground hover:text-foreground" href="#faq">
              FAQ
            </a>
          </nav>

          <div className="flex items-center gap-2">
            <TooltipProvider delayDuration={150}>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="ghost" className="hidden md:inline-flex h-9">
                    Документация <ExternalLink className="ml-2 h-3.5 w-3.5" aria-hidden />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>
                  <p>Скоро</p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
            <Button className="h-9">Войти</Button>

            <Sheet>
              <SheetTrigger asChild>
                <Button variant="ghost" size="icon" className="md:hidden" aria-label="Меню">
                  <Menu className="h-5 w-5" />
                </Button>
              </SheetTrigger>
              <SheetContent side="right" className="w-full sm:w-80">
                <SheetHeader>
                  <SheetTitle>Навигация</SheetTitle>
                </SheetHeader>
                <nav className="mt-6 flex flex-col gap-3">
                  <a className="text-sm" href="#features">
                    Возможности
                  </a>
                  <a className="text-sm" href="#stats">
                    Метрики
                  </a>
                  <a className="text-sm" href="#pricing">
                    Тарифы
                  </a>
                  <a className="text-sm" href="#faq">
                    FAQ
                  </a>
                </nav>
                <Separator className="my-6" />
                <Button className="w-full">Войти</Button>
              </SheetContent>
            </Sheet>
          </div>
        </div>
      </Container>
    </header>
  );
};

const Hero: React.FC = () => {
  const reduced = usePrefersReducedMotion();

  return (
    <section className="relative overflow-hidden">
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-muted to-background"
      />
      <Container>
        <div className="relative py-14 md:py-24">
          <motion.div
            {...(reduced ? {} : motionDefaults)}
            className="flex flex-col items-start gap-6"
          >
            <Badge className="rounded-full" variant="secondary">
              Новый релиз 1.0 · стабильный
            </Badge>
            <h1 className="text-3xl md:text-5xl font-semibold leading-tight tracking-tight">
              Промышленная Home-страница
              <span className="block text-muted-foreground">
                для сложной AI/Web3 платформы
              </span>
            </h1>
            <p className="max-w-2xl text-base md:text-lg text-muted-foreground">
              Адаптивный дизайн, доступность, наблюдаемость и безопасность — из коробки.
              Продуман для высокой нагрузки и быстрой навигации.
            </p>

            <div className="flex flex-col sm:flex-row gap-3">
              <Button className="h-11">
                Начать <ArrowRight className="ml-2 h-4 w-4" aria-hidden />
              </Button>
              <DemoVideoButton />
            </div>

            <div className="mt-2 flex items-center gap-4 text-xs text-muted-foreground">
              <div className="flex items-center gap-2">
                <Sparkles className="h-3.5 w-3.5" aria-hidden />
                Оптимизировано для Core Web Vitals
              </div>
              <div className="hidden sm:block">•</div>
              <div>SSR/SPA совместимо</div>
            </div>
          </motion.div>

          <motion.div
            {...(reduced ? {} : { ...motionDefaults, initial: { opacity: 0, y: 24 } })}
            className="mt-10 md:mt-16"
          >
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-lg">Быстрый старт</CardTitle>
                <CardDescription>
                  Подпишитесь, чтобы получить инструкции и доступ к ранним фичам.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <NewsletterForm />
              </CardContent>
              <CardFooter className="pt-0">
                <div className="w-full">
                  <Progress value={72} aria-label="Степень готовности релиза 72%" />
                  <p className="mt-2 text-xs text-muted-foreground">
                    72% дорожной карты готово. Обновляем метрики еженедельно.
                  </p>
                </div>
              </CardFooter>
            </Card>
          </motion.div>
        </div>
      </Container>
    </section>
  );
};

const Features: React.FC = () => (
  <section id="features" className="py-12 md:py-20">
    <Container>
      <div className="flex items-end justify-between gap-6">
        <SectionTitle
          title="Возможности платформы"
          subtitle="Сфокусированы на надежности, масштабировании и удобстве интеграции."
        />
        <Tabs defaultValue="core" className="hidden md:block">
          <TabsList>
            <TabsTrigger value="core">Core</TabsTrigger>
            <TabsTrigger value="security">Security</TabsTrigger>
            <TabsTrigger value="ai">AI</TabsTrigger>
          </TabsList>
        </Tabs>
      </div>

      <div className="mt-8 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
        {FEATURES.map((f, i) => (
          <motion.div key={f.title} {...motionDefaults} transition={{ delay: i * 0.05 }}>
            <FeatureCard feature={f} />
          </motion.div>
        ))}
      </div>
    </Container>
  </section>
);

const Stats: React.FC = () => (
  <section id="stats" className="py-12 md:py-20 bg-muted/30">
    <Container>
      <SectionTitle
        title="Проверенные метрики"
        subtitle="Реальные показатели эксплуатации. Ценности и ограничения задокументированы."
      />
      <div className="mt-8 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        {STATS.map((s, i) => (
          <motion.div key={s.label} {...motionDefaults} transition={{ delay: i * 0.05 }}>
            <StatCard stat={s} />
          </motion.div>
        ))}
      </div>
    </Container>
  </section>
);

const Pricing: React.FC = () => (
  <section id="pricing" className="py-12 md:py-20">
    <Container>
      <SectionTitle
        title="Прозрачные тарифы"
        subtitle="Гибкая модель — начните с малого и масштабируйтесь, когда потребуется."
      />
      <div className="mt-8 grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="relative">
          <CardHeader>
            <CardTitle>Starter</CardTitle>
            <CardDescription>Для пилотов и MVP</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-3xl font-semibold">0 ₽</p>
            <ul className="space-y-2 text-sm">
              <li className="flex gap-2">
                <CheckCircle2 className="h-4 w-4 mt-0.5" aria-hidden /> До 10k событий/мес
              </li>
              <li className="flex gap-2">
                <CheckCircle2 className="h-4 w-4 mt-0.5" aria-hidden /> Базовые отчеты
              </li>
              <li className="flex gap-2">
                <CheckCircle2 className="h-4 w-4 mt-0.5" aria-hidden /> Комьюнити-поддержка
              </li>
            </ul>
          </CardContent>
          <CardFooter>
            <Button className="w-full">Выбрать</Button>
          </CardFooter>
        </Card>

        <Card className="relative border-primary">
          <div className="absolute right-3 top-3">
            <Badge>Рекомендовано</Badge>
          </div>
          <CardHeader>
            <CardTitle>Pro</CardTitle>
            <CardDescription>Для растущих команд</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-3xl font-semibold">29 900 ₽</p>
            <ul className="space-y-2 text-sm">
              <li className="flex gap-2">
                <CheckCircle2 className="h-4 w-4 mt-0.5" aria-hidden /> 5M событий/сутки
              </li>
              <li className="flex gap-2">
                <CheckCircle2 className="h-4 w-4 mt-0.5" aria-hidden /> SSO, аудит, алерты
              </li>
              <li className="flex gap-2">
                <CheckCircle2 className="h-4 w-4 mt-0.5" aria-hidden /> Приоритетная поддержка
              </li>
            </ul>
          </CardContent>
          <CardFooter>
            <Button className="w-full">Выбрать</Button>
          </CardFooter>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Enterprise</CardTitle>
            <CardDescription>Под ваши требования</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-3xl font-semibold">Custom</p>
            <ul className="space-y-2 text-sm">
              <li className="flex gap-2">
                <CheckCircle2 className="h-4 w-4 mt-0.5" aria-hidden /> Выделенные инсталляции
              </li>
              <li className="flex gap-2">
                <CheckCircle2 className="h-4 w-4 mt-0.5" aria-hidden /> DPA/SOC 2/GDPR процессы
              </li>
              <li className="flex gap-2">
                <CheckCircle2 className="h-4 w-4 mt-0.5" aria-hidden /> SLA и инженер SRE-онколл
              </li>
            </ul>
          </CardContent>
          <CardFooter>
            <Button variant="outline" className="w-full">
              Связаться с отделом
            </Button>
          </CardFooter>
        </Card>
      </div>
    </Container>
  </section>
);

const Testimonials: React.FC = () => (
  <section className="py-12 md:py-20 bg-muted/30">
    <Container>
      <SectionTitle
        title="Отзывы команд"
        subtitle="Мы собираем обратную связь и используем её для улучшения дорожной карты."
      />
      <div className="mt-8 grid grid-cols-1 md:grid-cols-3 gap-6">
        {TESTIMONIALS.map((t, i) => (
          <motion.div key={t.name} {...motionDefaults} transition={{ delay: i * 0.05 }}>
            <TestimonialCard t={t} />
          </motion.div>
        ))}
      </div>
    </Container>
  </section>
);

const FAQ: React.FC = () => (
  <section id="faq" className="py-12 md:py-20">
    <Container>
      <SectionTitle title="FAQ" subtitle="Коротко о частых вопросах." />
      <div className="mt-8 grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Совместимо ли с SSR?</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            Да, компоненты и эффекты написаны осторожно, без обращения к window при рендере.
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Поддерживается ли i18n?</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            Вынесите строки в ресурсные файлы и передайте в пропсы — структура гибкая.
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Можно ли кастомизировать темы?</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            Да, через CSS-переменные Tailwind и конфиг shadcn/ui.
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Как подключить аналитику?</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            Рекомендуется отправлять события на сервер, а не напрямую в сторонние SDK.
          </CardContent>
        </Card>
      </div>
    </Container>
  </section>
);

const Footer: React.FC = () => (
  <footer className="border-t py-10">
    <Container>
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
        <a href="/" className="flex items-center gap-3">
          <HeroLogo />
          <div className="flex flex-col">
            <span className="text-sm font-semibold tracking-tight">Aethernova</span>
            <span className="text-xs text-muted-foreground">© {new Date().getFullYear()}</span>
          </div>
        </a>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-6 text-sm">
          <div className="space-y-2">
            <div className="font-medium">Продукт</div>
            <a className="text-muted-foreground hover:text-foreground" href="#features">
              Возможности
            </a>
            <a className="text-muted-foreground hover:text-foreground" href="#pricing">
              Тарифы
            </a>
          </div>
          <div className="space-y-2">
            <div className="font-medium">Ресурсы</div>
            <a className="text-muted-foreground hover:text-foreground" href="#">
              Документация
            </a>
            <a className="text-muted-foreground hover:text-foreground" href="#">
              API
            </a>
          </div>
          <div className="space-y-2">
            <div className="font-medium">Компания</div>
            <a className="text-muted-foreground hover:text-foreground" href="#">
              О нас
            </a>
            <a className="text-muted-foreground hover:text-foreground" href="#">
              Контакты
            </a>
          </div>
          <div className="space-y-2">
            <div className="font-medium">Право</div>
            <a className="text-muted-foreground hover:text-foreground" href="#">
              Политика конфиденциальности
            </a>
            <a className="text-muted-foreground hover:text-foreground" href="#">
              Условия
            </a>
          </div>
        </div>
      </div>
    </Container>
  </footer>
);

const HomePage: React.FC = () => {
  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      <main className="flex-1">
        <Hero />
        <Features />
        <Stats />
        <Pricing />
        <Testimonials />
        <FAQ />
      </main>
      <Footer />
    </div>
  );
};

export default HomePage;
