﻿using HealthServices.Data;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.EntityFrameworkCore;
using MimeKit;
using PatientServices.Models;
using PatientServices.Models.Patient;
using PatientServices.Repositories.Interfaces;

namespace PatientServices.Repositories
{
    public class NotificationRepository : INotificationRepository
    {
        private readonly PatientDbContext _context;

        public NotificationRepository(PatientDbContext context)
        {
            _context = context;
        }

        public async Task<IEnumerable<Notification>> GetNotificationsAsync()
        {
            return await _context.Notifications.ToListAsync();
        }

        public async Task<Notification> GetNotificationByIdAsync(int id)
        {
            return await _context.Notifications.FindAsync(id);
        }

        public async Task<int> AddNotificationAsync(Notification notification)
        {
            _context.Notifications.Add(notification);
            await _context.SaveChangesAsync();
            return notification.NotificationId;
        }

        public async Task UpdateNotificationAsync(Notification notification)
        {
            _context.Entry(notification).State = EntityState.Modified;
            await _context.SaveChangesAsync();
        }

        public async Task DeleteNotificationAsync(int id)
        {
            var notification = await _context.Notifications.FindAsync(id);
            _context.Notifications.Remove(notification);
            await _context.SaveChangesAsync();
        }

        public bool NotificationExists(int id)
        {
            return _context.Notifications.Any(e => e.NotificationId == id);
        }
        public async Task<bool> SendNotificationAsync(NotificationRequest notificationRequest)
        {
            var email = new MimeKit.MimeMessage();
            email.Sender = MimeKit.MailboxAddress.Parse(notificationRequest.SenderMail);

            email.To.Add(MimeKit.MailboxAddress.Parse(notificationRequest.ToEmail));
            email.Subject = notificationRequest.Subject;
            var builder = new MimeKit.BodyBuilder();
            if (notificationRequest.Attachments != null)
            {
                byte[] fileBytes;
                foreach (var file in notificationRequest.Attachments)
                {
                    if (file.Length > 0)
                    {
                        using (var ms = new MemoryStream())
                        {
                            file.CopyTo(ms);
                            fileBytes = ms.ToArray();
                        }
                        builder.Attachments.Add(file.FileName, fileBytes, ContentType.Parse(file.ContentType));
                    }
                }
            }
            builder.HtmlBody = notificationRequest.Body;
            email.Body = builder.ToMessageBody();
            using var smtp = new SmtpClient();
            smtp.Connect(notificationRequest.Host, notificationRequest.Port, SecureSocketOptions.StartTls);
            smtp.Authenticate(notificationRequest.SenderMail, notificationRequest.Password);
            await smtp.SendAsync(email);
            smtp.Disconnect(true);

            return true;
        }
    }
}
