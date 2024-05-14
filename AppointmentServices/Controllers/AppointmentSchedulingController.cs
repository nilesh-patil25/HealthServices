﻿using AppointmentServices.Models;
using AppointmentServices.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AppointmentServices.Controllers
{

    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class AppointmentSchedulingController : ControllerBase
    {
        private readonly IAppointmentService _appointmentService;

        public AppointmentSchedulingController(IAppointmentService appointmentService)
        {
            _appointmentService = appointmentService;
        }

        [HttpPost]
        public IActionResult CreateAppointment([FromBody] Appointment appointment)
        {
            _appointmentService.CreateAppointment(appointment);
            return Ok();
        }
    }
}