import React from 'react';
import { cn } from '../../utils/cn';

interface CardProps {
  children: React.ReactNode;
  className?: string;
}

interface CardHeaderProps {
  children: React.ReactNode;
  className?: string;
}

interface CardTitleProps {
  children: React.ReactNode;
  className?: string;
}

interface CardContentProps {
  children: React.ReactNode;
  className?: string;
}

export const Card: React.FC<CardProps> = ({ children, className }) => {
  return (
    <div className={cn("bg-white shadow-sm border border-gray-200 rounded-lg", className)}>
      {children}
    </div>
  );
};

export const CardHeader: React.FC<CardHeaderProps> = ({ children, className }) => {
  return (
    <div className={cn("px-4 py-3 border-b border-gray-200", className)}>
      {children}
    </div>
  );
};

export const CardTitle: React.FC<CardTitleProps> = ({ children, className }) => {
  return (
    <h3 className={cn("font-medium text-gray-900", className)}>
      {children}
    </h3>
  );
};

export const CardContent: React.FC<CardContentProps> = ({ children, className }) => {
  return (
    <div className={cn("px-4 py-3", className)}>
      {children}
    </div>
  );
};
