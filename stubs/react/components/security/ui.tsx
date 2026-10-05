import React from 'react';

export function Card({
    children,
    className = '',
    flush = false,
    style,
}: {
    children: React.ReactNode;
    className?: string;
    flush?: boolean;
    style?: React.CSSProperties;
}) {
    return (
        <div
            className={`sec-card ${flush ? 'sec-card-flush' : ''} ${className}`}
            style={style}
        >
            {children}
        </div>
    );
}

export function CardHeader({
    children,
    className = '',
    style,
}: {
    children: React.ReactNode;
    className?: string;
    style?: React.CSSProperties;
}) {
    return (
        <div className={`sec-card-header ${className}`} style={style}>
            {children}
        </div>
    );
}

export function CardTitle({
    children,
    className = '',
    style,
}: {
    children: React.ReactNode;
    className?: string;
    style?: React.CSSProperties;
}) {
    return (
        <h3 className={`sec-card-title ${className}`} style={style}>
            {children}
        </h3>
    );
}

export function CardDescription({
    children,
    className = '',
    style,
}: {
    children: React.ReactNode;
    className?: string;
    style?: React.CSSProperties;
}) {
    return (
        <p className={`sec-card-subtitle ${className}`} style={style}>
            {children}
        </p>
    );
}

export function CardContent({
    children,
    className = '',
    style,
}: {
    children: React.ReactNode;
    className?: string;
    style?: React.CSSProperties;
}) {
    return (
        <div className={className} style={{ padding: '0', ...style }}>
            {children}
        </div>
    );
}

export function Button({
    children,
    variant = 'secondary',
    size = 'md',
    className = '',
    disabled = false,
    onClick,
    type = 'button',
    style,
    dangerouslySetInnerHTML,
}: {
    children?: React.ReactNode;
    variant?: 'primary' | 'secondary' | 'danger' | 'ghost' | 'outline' | 'default';
    size?: 'sm' | 'md';
    className?: string;
    disabled?: boolean;
    onClick?: (e: React.MouseEvent<HTMLButtonElement>) => void;
    type?: 'button' | 'submit' | 'reset';
    style?: React.CSSProperties;
    dangerouslySetInnerHTML?: { __html: string };
}) {
    let variantClass = 'sec-btn-secondary';
    if (variant === 'primary' || variant === 'default') variantClass = 'sec-btn-primary';
    if (variant === 'danger') variantClass = 'sec-btn-danger';
    if (variant === 'ghost') variantClass = 'sec-btn-ghost';
    if (variant === 'outline') variantClass = 'sec-btn-secondary';

    const sizeClass = size === 'sm' ? 'sec-btn-sm' : '';

    return (
        <button
            type={type}
            disabled={disabled}
            onClick={onClick}
            className={`sec-btn ${variantClass} ${sizeClass} ${className}`}
            style={{ opacity: disabled ? 0.5 : 1, cursor: disabled ? 'not-allowed' : 'pointer', ...style }}
            dangerouslySetInnerHTML={dangerouslySetInnerHTML}
        >
            {children}
        </button>
    );
}

export function Badge({
    children,
    variant = 'default',
    className = '',
    style,
}: {
    children: React.ReactNode;
    variant?: 'critical' | 'high' | 'medium' | 'low' | 'success' | 'default' | 'outline';
    className?: string;
    style?: React.CSSProperties;
}) {
    let variantClass = 'sec-badge-low';
    if (variant === 'critical') variantClass = 'sec-badge-critical';
    if (variant === 'high') variantClass = 'sec-badge-high';
    if (variant === 'medium') variantClass = 'sec-badge-medium';
    if (variant === 'success') variantClass = 'sec-badge-success';

    return (
        <span className={`sec-badge ${variantClass} ${className}`} style={style}>
            {children}
        </span>
    );
}

export function Input({
    type = 'text',
    value,
    defaultValue,
    onChange,
    placeholder,
    className = '',
    required = false,
    min,
    max,
    style,
}: {
    type?: string;
    value?: string | number;
    defaultValue?: string | number;
    onChange?: (e: React.ChangeEvent<HTMLInputElement>) => void;
    placeholder?: string;
    className?: string;
    required?: boolean;
    min?: number | string;
    max?: number | string;
    style?: React.CSSProperties;
}) {
    return (
        <input
            type={type}
            value={value}
            defaultValue={defaultValue}
            onChange={onChange}
            placeholder={placeholder}
            required={required}
            min={min}
            max={max}
            className={`sec-input ${className}`}
            style={style}
        />
    );
}

export function Label({
    children,
    htmlFor,
    className = '',
    style,
}: {
    children: React.ReactNode;
    htmlFor?: string;
    className?: string;
    style?: React.CSSProperties;
}) {
    return (
        <label htmlFor={htmlFor} className={`sec-label ${className}`} style={style}>
            {children}
        </label>
    );
}
