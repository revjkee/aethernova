import React, { useState, useEffect } from "react";

interface FilterPanelProps {
  categories: string[];
  brands: string[];
  onFilterChange: (filters: Filters) => void;
}

interface Filters {
  category: string | null;
  brand: string | null;
  priceRange: [number, number] | null;
}

const FilterPanel: React.FC<FilterPanelProps> = ({ categories, brands, onFilterChange }) => {
  const [category, setCategory] = useState<string | null>(null);
  const [brand, setBrand] = useState<string | null>(null);
  const [priceMin, setPriceMin] = useState<number | "">(0);
  const [priceMax, setPriceMax] = useState<number | "">("");

  useEffect(() => {
    const priceRange = priceMax === "" ? null : [priceMin || 0, Number(priceMax)] as [number, number];
    onFilterChange({ category, brand, priceRange });
  }, [category, brand, priceMin, priceMax, onFilterChange]);

  return (
    <div className="filter-panel">
      <div>
        <label>Категория:</label>
        <select value={category ?? ""} onChange={e => setCategory(e.target.value || null)}>
          <option value="">Все</option>
          {categories.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
      </div>

      <div>
        <label>Бренд:</label>
        <select value={brand ?? ""} onChange={e => setBrand(e.target.value || null)}>
          <option value="">Все</option>
          {brands.map(b => <option key={b} value={b}>{b}</option>)}
        </select>
      </div>

      <div>
        <label>Цена от:</label>
        <input
          type="number"
          min={0}
          value={priceMin}
          onChange={e => setPriceMin(e.target.value === "" ? "" : Number(e.target.value))}
        />
      </div>

      <div>
        <label>Цена до:</label>
        <input
          type="number"
          min={0}
          value={priceMax}
          onChange={e => setPriceMax(e.target.value === "" ? "" : Number(e.target.value))}
        />
      </div>
    </div>
  );
};

export default FilterPanel;
