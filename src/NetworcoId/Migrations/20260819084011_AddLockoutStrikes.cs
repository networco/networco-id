using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace NetworcoId.Migrations
{
    /// <inheritdoc />
    public partial class AddLockoutStrikes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "lockout_strikes",
                table: "user_credentials",
                type: "integer",
                nullable: false,
                defaultValue: 0);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "lockout_strikes",
                table: "user_credentials");
        }
    }
}
