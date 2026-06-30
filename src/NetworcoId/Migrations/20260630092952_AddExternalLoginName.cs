using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace NetworcoId.Migrations
{
    /// <inheritdoc />
    public partial class AddExternalLoginName : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "first_name",
                table: "user_external_logins",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "last_name",
                table: "user_external_logins",
                type: "text",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "first_name",
                table: "user_external_logins");

            migrationBuilder.DropColumn(
                name: "last_name",
                table: "user_external_logins");
        }
    }
}
