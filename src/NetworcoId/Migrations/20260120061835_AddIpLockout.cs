using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace NetworcoId.Migrations
{
    /// <inheritdoc />
    public partial class AddIpLockout : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ip_lockouts",
                columns: table => new
                {
                    ip_address = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: false),
                    failed_attempts = table.Column<int>(type: "integer", nullable: false, defaultValue: 0),
                    last_attempt_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    locked_until = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ip_lockouts", x => x.ip_address);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ip_lockouts_locked_until",
                table: "ip_lockouts",
                column: "locked_until");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ip_lockouts");
        }
    }
}
