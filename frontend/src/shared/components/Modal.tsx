import React from 'react';

type ModalProps = {
	title?: string;
	children?: React.ReactNode;
	onClose?: () => void;
	open?: boolean;
};

export const Modal: React.FC<ModalProps> = ({ title, children, onClose, open = true }) => {
	if (!open) return null;
	return (
		<div
			role="dialog"
			aria-modal="true"
			aria-label={title || 'modal'}
			style={{
				position: 'fixed',
				inset: 0,
				display: 'flex',
				alignItems: 'center',
				justifyContent: 'center',
				background: 'rgba(2,6,23,0.5)',
				zIndex: 1000,
			}}
			onClick={onClose}
		>
			<div
				role="document"
				onClick={(e) => e.stopPropagation()}
				style={{
					background: '#fff',
					borderRadius: 8,
					maxWidth: 720,
					width: '90%',
					padding: 16,
					boxShadow: '0 6px 18px rgba(2,6,23,0.2)',
				}}
			>
				{title && <h3 style={{marginTop: 0}}>{title}</h3>}
				<div>{children}</div>
				<div style={{marginTop: 12, textAlign: 'right'}}>
					<button onClick={onClose} style={{padding: '6px 10px'}}>Close</button>
				</div>
			</div>
		</div>
	);
};

export default Modal;
