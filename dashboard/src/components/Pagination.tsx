'use client';

import { ChevronLeft, ChevronRight } from 'lucide-react';
import { cn } from '@/lib/utils';

interface PaginationProps {
  currentPage: number;
  totalPages: number;
  onPageChange: (page: number) => void;
  className?: string;
}

export function Pagination({
  currentPage,
  totalPages,
  onPageChange,
  className,
}: PaginationProps) {
  const pages = generatePageNumbers(currentPage, totalPages);

  if (totalPages <= 1) return null;

  return (
    <div className={cn('flex items-center justify-center gap-1', className)}>
      <button
        onClick={() => onPageChange(currentPage - 1)}
        disabled={currentPage === 1}
        className="p-2 rounded-lg hover:bg-bg-tertiary disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        aria-label="Previous page"
      >
        <ChevronLeft size={16} />
      </button>

      {pages.map((page, index) => (
        <span key={index}>
          {page === '...' ? (
            <span className="px-3 py-2 text-text-tertiary">...</span>
          ) : (
            <button
              onClick={() => onPageChange(page as number)}
              className={cn(
                'px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                currentPage === page
                  ? 'bg-primary-500/10 text-primary-500'
                  : 'hover:bg-bg-tertiary text-text-secondary'
              )}
            >
              {page}
            </button>
          )}
        </span>
      ))}

      <button
        onClick={() => onPageChange(currentPage + 1)}
        disabled={currentPage === totalPages}
        className="p-2 rounded-lg hover:bg-bg-tertiary disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        aria-label="Next page"
      >
        <ChevronRight size={16} />
      </button>
    </div>
  );
}

function generatePageNumbers(current: number, total: number): (number | '...')[] {
  const pages: (number | '...')[] = [];
  const showPages = 5;
  const sidePages = Math.floor(showPages / 2);

  if (total <= showPages + 2) {
    // Show all pages
    for (let i = 1; i <= total; i++) {
      pages.push(i);
    }
  } else {
    // Always show first page
    pages.push(1);

    // Calculate start and end of middle section
    let start = Math.max(2, current - sidePages);
    let end = Math.min(total - 1, current + sidePages);

    // Adjust if we're near the start
    if (current <= sidePages + 1) {
      end = showPages;
    }

    // Adjust if we're near the end
    if (current >= total - sidePages) {
      start = total - showPages + 1;
    }

    // Add ellipsis if needed before middle section
    if (start > 2) {
      pages.push('...');
    }

    // Add middle pages
    for (let i = start; i <= end; i++) {
      pages.push(i);
    }

    // Add ellipsis if needed after middle section
    if (end < total - 1) {
      pages.push('...');
    }

    // Always show last page
    pages.push(total);
  }

  return pages;
}
