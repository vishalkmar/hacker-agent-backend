import PDFDocument from 'pdfkit';

const fmtDate = (d) =>
  new Date(d).toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' });

// Generate a PDF voucher / plan contract. Returns { base64, voucherNo }.
export function generateVoucherPdf({ user, plan, amount, orderId, paymentId, purchasedAt, expiresAt }) {
  const voucherNo = 'CM-' + String(orderId || Date.now()).replace(/[^a-zA-Z0-9]/g, '').slice(-10).toUpperCase();
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ size: 'A4', margin: 50 });
      const chunks = [];
      doc.on('data', (c) => chunks.push(c));
      doc.on('end', () => resolve({ base64: Buffer.concat(chunks).toString('base64'), voucherNo }));

      const CYAN = '#0891b2';
      const DARK = '#0f172a';
      const MUT = '#64748b';

      // Header
      doc.rect(0, 0, doc.page.width, 90).fill('#0b1220');
      doc.fillColor('#22d3ee').fontSize(22).font('Helvetica-Bold').text('CypherMind AI', 50, 32);
      doc.fillColor('#8aa0b8').fontSize(10).font('Helvetica').text('Plan Purchase Voucher & Contract', 50, 60);
      doc.fillColor('#8aa0b8').fontSize(10).text('Voucher: ' + voucherNo, 0, 40, { align: 'right', width: doc.page.width - 50 });

      doc.moveDown(4);
      doc.fillColor(DARK).fontSize(16).font('Helvetica-Bold').text('Payment Successful', 50, 120);
      doc.fillColor(MUT).fontSize(10).font('Helvetica')
        .text('This voucher confirms the plan booked on the CypherMind AI platform.', 50, 142);

      // Details table
      let y = 180;
      const row = (k, v) => {
        doc.fillColor(MUT).fontSize(10).font('Helvetica').text(k, 60, y);
        doc.fillColor(DARK).fontSize(11).font('Helvetica-Bold').text(String(v), 230, y);
        y += 26;
      };
      doc.roundedRect(50, 165, doc.page.width - 100, 250, 8).stroke('#e2e8f0');
      y = 180;
      row('Billed to', user?.display_name || user?.email || '—');
      row('Email', user?.email || '—');
      row('Plan', (plan?.name || plan?.code || '—') + '  (' + (plan?.period || 'monthly') + ')');
      row('Amount paid', 'INR ' + Number(amount || plan?.price_inr || 0).toFixed(2));
      row('Order ID', orderId || '—');
      if (paymentId) row('Payment ID', paymentId);
      row('Purchased on', fmtDate(purchasedAt || Date.now()));
      row('Valid till', expiresAt ? fmtDate(expiresAt) : 'No expiry');
      row('Daily message limit', plan?.daily_limit ?? '—');

      // Contract note
      doc.fillColor(DARK).fontSize(12).font('Helvetica-Bold').text('Agreement', 50, 440);
      doc.fillColor(MUT).fontSize(9).font('Helvetica').text(
        `By purchasing this plan, the user has booked the above CypherMind AI plan for the stated ` +
          `validity period. The platform is provided for educational and authorized security-testing ` +
          `purposes; the user accepts full responsibility for their use of the platform as per the ` +
          `Terms of Service accepted at signup. This voucher serves as proof of purchase.`,
        50, 460, { width: doc.page.width - 100, align: 'justify' }
      );

      doc.fillColor(CYAN).fontSize(9).text('CypherMind AI — Autonomous Security Copilot', 50, doc.page.height - 70);
      doc.fillColor(MUT).fontSize(8).text('This is a system-generated voucher.', 50, doc.page.height - 56);

      doc.end();
    } catch (e) {
      reject(e);
    }
  });
}
