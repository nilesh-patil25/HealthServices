﻿using AppointmentServices.Models;
using AppointmentServices.Repositories.IRepository;
using AppointmentServices.Services;
using Confluent.Kafka;
using Newtonsoft.Json;
using System.Threading.Tasks;

namespace AppointmentServices.Services
{
    public class AppointmentService : IAppointmentService
    {
        private readonly IAppointmentSchedulingRepository _appointmentRepository;
        private readonly ProducerConfig _kafkaConfig;

        public AppointmentService(IAppointmentSchedulingRepository appointmentRepository)
        {
            _appointmentRepository = appointmentRepository;
            _kafkaConfig = new ProducerConfig
            {
                BootstrapServers = "localhost:9092"
            };
        }
        public void CreateAppointment(Appointment appointment)
        {
            _appointmentRepository.CreateAppointment(appointment);
        }

        public async Task CreateAppointmentAsync(Appointment appointment)
        {
            _appointmentRepository.CreateAppointment(appointment);

            // Serialize appointment object to JSON
            var appointmentJson = JsonConvert.SerializeObject(appointment);

            // Send appointment data to Kafka
            using var producer = new ProducerBuilder<Null, string>(_kafkaConfig).Build();
            await producer.ProduceAsync(KafkaTopics.AppointmentTopic, new Message<Null, string> { Value = appointmentJson });
        }
    }
}